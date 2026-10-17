"""Threat Feed collection and read service."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

import httpx
from pydantic import HttpUrl

from .evidence import targeting
from .logic import (
    canonical_url,
    classify_region,
    classify_topic,
    deterministic_summary,
    explicit_severity,
    extract_entities,
    stable_id,
)
from .models import (
    FeedHomeResponse,
    FeedHomeSection,
    FeedListResponse,
    FeedRefreshResult,
    FeedRegion,
    FeedSourceStatus,
    FeedSummary,
    FeedTopic,
    RegionCount,
    SourceEntry,
    ThreatFeedItem,
    VulnerabilityListResponse,
)
from .sources import SOURCE_OPTIONS, SOURCES, SourceDefinition, fetch_source
from .storage import FeedStorage
from .vulnerabilities import link_reports, sync_nvd, vulnerability_list

RETENTION_DAYS = 30
PUBLIC_REFRESH_COOLDOWN = timedelta(minutes=30)
HOME_CACHE_SECONDS = 300
HOME_CACHE_SIZE = 32
_logger = logging.getLogger("threatlens.threat_feed")


class FeedStorageError(RuntimeError):
    """A source downloaded successfully but its normalized records could not be saved."""


async def collect_ioc_reports(feed: FeedStorage, now: datetime) -> int:
    # Lazy composition avoids a cycle through the feed package's public service export.
    from ..ioc_feed.collector import collect
    from ..ioc_feed.storage import get_storage

    return await collect(get_storage(feed), now)


class ThreatFeedService:
    def __init__(self, storage: FeedStorage) -> None:
        self.storage = storage
        self._home_cache: OrderedDict[
            tuple[str, str, int | None, int, str, str], tuple[float, FeedHomeResponse]
        ] = OrderedDict()
        self._home_cache_lock = Lock()
        self._collection_storage_lock = Lock()
        self._vulnerability_cache: OrderedDict[
            tuple[str, str, str, str, int, int, int, str], tuple[float, VulnerabilityListResponse]
        ] = OrderedDict()

    async def refresh(self, *, force: bool = False) -> FeedRefreshResult:
        owner = str(uuid4())
        now = datetime.now(UTC)
        if not self.storage.acquire_refresh(owner, now, force=force):
            last = self._timestamp("last_refresh_attempt") or self._timestamp("last_refresh")
            return FeedRefreshResult(
                status="cooldown",
                started_at=now,
                completed_at=now,
                next_refresh_at=last + PUBLIC_REFRESH_COOLDOWN if last else now,
            )
        try:
            return await self._refresh_sources(force=force)
        finally:
            self.storage.release_refresh(owner)

    async def _refresh_sources(self, *, force: bool = False) -> FeedRefreshResult:
        now = datetime.now(UTC)
        last = self._timestamp("last_refresh")
        next_refresh = last + PUBLIC_REFRESH_COOLDOWN if last else None
        if not force and next_refresh and now < next_refresh:
            return FeedRefreshResult(
                status="cooldown",
                started_at=now,
                completed_at=now,
                next_refresh_at=next_refresh,
            )
        slots = asyncio.Semaphore(4)

        async def collect(source: SourceDefinition) -> tuple[int, int]:
            async with slots:
                return await self._collect(source, now)

        results = await asyncio.gather(
            *(collect(source) for source in SOURCES), return_exceptions=True
        )
        added = seen = succeeded = 0
        errors: list[str] = []
        for source, result in zip(SOURCES, results, strict=True):
            if isinstance(result, BaseException):
                errors.append(f"{source.name}: unavailable")
                await asyncio.to_thread(self._source_error, source, now, result)
                continue
            source_added, source_seen = result
            added += source_added
            seen += source_seen
            succeeded += 1
        try:
            await sync_nvd(self.storage, now)
            succeeded += 1
        except Exception as error:
            errors.append("NVD: unavailable")
            self.storage.set_state("nvd_status", "delayed")
            self._source_error(
                SourceDefinition("nvd", "NVD", "json", "https://nvd.nist.gov"), now, error
            )
        try:
            await collect_ioc_reports(self.storage, now)
        except Exception:
            _logger.warning("IOC collection unavailable; existing reports retained")
            errors.append("IOC reports: unavailable")
        from ..ioc_feed.service import clear_cache

        clear_cache()
        from .workflow import clear_workflow_cache

        clear_workflow_cache()
        if succeeded:
            self.storage.delete_before(now - timedelta(days=RETENTION_DAYS))
            self.storage.save_vulnerabilities(
                link_reports(self.storage.list_vulnerabilities(), self.storage.list_items(), now)
            )
            self.storage.prune_vulnerabilities(now - timedelta(days=RETENTION_DAYS))
            self.storage.set_state("last_refresh", now.isoformat())
        completed = datetime.now(UTC)
        refresh = FeedRefreshResult(
            status="completed" if succeeded else "failed",
            started_at=now,
            completed_at=completed,
            sources_attempted=len(SOURCES) + 1,
            sources_succeeded=succeeded,
            items_added=added,
            items_seen=seen,
            errors=tuple(errors),
            next_refresh_at=now + PUBLIC_REFRESH_COOLDOWN,
        )
        self.storage.save_refresh(refresh)
        if succeeded:
            self.clear_home_cache()
        return refresh

    def clear_home_cache(self) -> None:
        with self._home_cache_lock:
            self._home_cache.clear()
            self._vulnerability_cache.clear()

    def vulnerabilities(
        self,
        *,
        query: str = "",
        category: str = "all",
        severity: str = "",
        source: str = "",
        hours: int = 168,
        page: int = 1,
        page_size: int = 20,
        sort: str = "newest",
    ) -> VulnerabilityListResponse:
        key = (query.strip().lower(), category, severity, source, hours, page, page_size, sort)
        stamp = time.monotonic()
        with self._home_cache_lock:
            cached = self._vulnerability_cache.get(key)
            if cached and cached[0] > stamp:
                return cached[1]
        result = vulnerability_list(
            self.storage,
            query=query,
            category=category,
            severity=severity,
            source=source,
            hours=hours,
            page=page,
            page_size=page_size,
            sort=sort,
        )
        with self._home_cache_lock:
            self._vulnerability_cache[key] = (stamp + HOME_CACHE_SECONDS, result)
            self._vulnerability_cache.move_to_end(key)
            while len(self._vulnerability_cache) > HOME_CACHE_SIZE:
                self._vulnerability_cache.popitem(last=False)
        return result

    def home(
        self,
        *,
        query: str | None = None,
        topic: FeedTopic | None = None,
        hours: int | None = None,
        limit_per_region: int = 5,
        sort: str = "newest",
        source: str | None = None,
    ) -> FeedHomeResponse:
        key = (
            (query or "").strip().lower(),
            topic.value if topic else "",
            hours,
            limit_per_region,
            sort,
            source or "",
        )
        now_monotonic = time.monotonic()
        with self._home_cache_lock:
            cached = self._home_cache.get(key)
            if cached and cached[0] > now_monotonic:
                self._home_cache.move_to_end(key)
                return cached[1]
            if cached:
                del self._home_cache[key]

        from .queries import database_backed, home_page

        if database_backed(self.storage):
            response = home_page(
                self.storage,
                query=query,
                topic=topic,
                hours=hours,
                limit_per_region=limit_per_region,
                sort=sort,
                source=source,
            )
            with self._home_cache_lock:
                self._home_cache[key] = (now_monotonic + HOME_CACHE_SECONDS, response)
                self._home_cache.move_to_end(key)
                while len(self._home_cache) > HOME_CACHE_SIZE:
                    self._home_cache.popitem(last=False)
            return response
        snapshot = self.storage.home_snapshot()
        now = datetime.now(UTC)
        recent_cutoff = now - timedelta(hours=24)
        filtered_cutoff = now - timedelta(hours=hours) if hours else None
        needle = key[0]
        sections: dict[FeedRegion, FeedHomeSection] = {}
        for region in FeedRegion:
            matching = tuple(
                item
                for item in snapshot.items
                if item.region == region
                and (not source or item.source_id == source)
                and (topic is None or item.topic == topic)
                and (filtered_cutoff is None or item.published_at >= filtered_cutoff)
                and (
                    not needle
                    or needle in f"{item.title} {item.summary} {item.source_name}".lower()
                )
            )
            matching = tuple(
                sorted(
                    matching,
                    key=lambda item: (item.published_at, item.id),
                    reverse=sort != "oldest",
                )
            )
            sections[region] = FeedHomeSection(
                items=matching[:limit_per_region], total=len(matching)
            )

        refreshed = datetime.fromisoformat(snapshot.last_refresh) if snapshot.last_refresh else None
        summary = FeedSummary(
            regions={
                region: RegionCount(
                    total=sum(item.region == region for item in snapshot.items),
                    recent=sum(
                        item.region == region and item.published_at >= recent_cutoff
                        for item in snapshot.items
                    ),
                )
                for region in FeedRegion
            },
            critical=sum(item.severity == "critical" for item in snapshot.items),
            new_iocs=sum(
                len(item.entities) for item in snapshot.items if item.published_at >= recent_cutoff
            ),
            last_refreshed_at=refreshed,
            next_refresh_at=refreshed + PUBLIC_REFRESH_COOLDOWN if refreshed else None,
            source_errors=sum(source.last_error_code is not None for source in snapshot.sources),
        )
        response = FeedHomeResponse(
            summary=summary, sections=sections, generated_at=now, source_options=SOURCE_OPTIONS
        )
        with self._home_cache_lock:
            self._home_cache[key] = (now_monotonic + HOME_CACHE_SECONDS, response)
            self._home_cache.move_to_end(key)
            while len(self._home_cache) > HOME_CACHE_SIZE:
                self._home_cache.popitem(last=False)
        return response

    async def _collect(self, source: SourceDefinition, now: datetime) -> tuple[int, int]:
        entries = await fetch_source(source)
        try:
            return await asyncio.to_thread(self._persist, source, entries, now)
        except Exception as error:
            raise FeedStorageError("Source records could not be saved") from error

    def _persist(
        self, source: SourceDefinition, entries: tuple[SourceEntry, ...], now: datetime
    ) -> tuple[int, int]:
        # Synchronous database work must not starve other source HTTP connections.
        # Serialize read/merge/write operations to avoid competing within one refresh.
        with self._collection_storage_lock:
            return self._persist_entries(source, entries, now)

    def _persist_entries(
        self, source: SourceDefinition, entries: tuple[SourceEntry, ...], now: datetime
    ) -> tuple[int, int]:
        items: list[ThreatFeedItem] = []
        cutoff = now - timedelta(days=RETENTION_DAYS)
        for entry in entries:
            topic = classify_topic(entry)
            region, relevance, reasons = classify_region(source.id, entry)
            items.append(
                ThreatFeedItem(
                    id=stable_id(source.id, entry.model_copy(update={"guid": None}))
                    if source.id == "singcert"
                    else stable_id(source.id, entry),
                    source_id=source.id,
                    source_name=source.name,
                    source_kind=source.kind,
                    guid=entry.guid,
                    title=entry.title,
                    excerpt=entry.excerpt,
                    summary=deterministic_summary(entry, topic),
                    url=HttpUrl(canonical_url(entry.url)),
                    published_at=entry.published_at,
                    collected_at=now,
                    region=region,
                    relevance=relevance,
                    region_reasons=reasons,
                    topic=topic,
                    severity=explicit_severity(entry, topic),
                    entities=extract_entities(entry),
                    vendor=entry.vendor,
                    product=entry.product,
                    targeting_evidence=targeting(
                        source.name, {"title": entry.title, "excerpt": entry.excerpt}
                    ),
                )
            )
        if source.id in {"nc4", "singcert"}:
            self.storage.repair_listing_items(items)
        added = self.storage.save_items(item for item in items if item.published_at >= cutoff)
        self.storage.save_source(
            FeedSourceStatus(
                id=source.id,
                name=source.name,
                kind=source.kind,
                last_success_at=now,
                last_attempt_at=now,
                last_added=added,
            )
        )
        return added, len(entries)

    def _source_error(self, source: SourceDefinition, now: datetime, error: BaseException) -> None:
        code = (
            "timeout"
            if isinstance(error, (TimeoutError, httpx.TimeoutException))
            else "storage_error"
            if isinstance(error, FeedStorageError)
            else f"http_{error.response.status_code}"
            if isinstance(error, httpx.HTTPStatusError)
            else "invalid_metadata"
            if isinstance(error, ValueError)
            else "source_unavailable"
        )
        _logger.exception("Threat feed source refresh failed: %s", source.id, exc_info=error)
        previous = next(
            (item for item in self.storage.list_sources() if item.id == source.id), None
        )
        messages = {
            "storage_error": "Downloaded source metadata could not be saved.",
            "timeout": "The source request timed out; saved reports remain available.",
            "invalid_metadata": "The source did not supply usable dated report metadata.",
            "http_403": "The publisher refused the public feed request (HTTP 403).",
            "http_400": "The publisher rejected the feed request (HTTP 400).",
            "http_429": "The publisher rate-limited the feed request (HTTP 429).",
        }
        self.storage.save_source(
            FeedSourceStatus(
                id=source.id,
                name=source.name,
                kind=source.kind,
                last_success_at=previous.last_success_at if previous else None,
                last_attempt_at=now,
                last_error_code=code,
                last_error=messages.get(code, "The source could not be refreshed safely."),
                last_added=previous.last_added if previous else 0,
            )
        )

    def list_items(
        self,
        *,
        region: FeedRegion | None = None,
        source: str | None = None,
        topic: FeedTopic | None = None,
        hours: int | None = None,
        query: str | None = None,
        page: int = 1,
        page_size: int = 20,
        sort: str = "newest",
    ) -> FeedListResponse:
        from .queries import database_backed, news_page

        if database_backed(self.storage):
            return news_page(
                self.storage,
                region=region,
                source=source,
                topic=topic,
                hours=hours,
                query=query,
                page=page,
                page_size=page_size,
                sort=sort,
            )
        items = self.storage.list_items()
        cutoff = datetime.now(UTC) - timedelta(hours=hours) if hours else None
        needle = (query or "").strip().lower()
        filtered = [
            item
            for item in items
            if (
                (region is None or item.region == region)
                and (source is None or item.source_id == source)
                and (topic is None or item.topic is topic)
                and (cutoff is None or item.published_at >= cutoff)
                and (
                    not needle
                    or needle in f"{item.title} {item.summary} {item.source_name}".lower()
                )
            )
        ]
        filtered.sort(key=lambda item: (item.published_at, item.id), reverse=sort != "oldest")
        start = (page - 1) * page_size
        return FeedListResponse(
            items=tuple(filtered[start : start + page_size]),
            total=len(filtered),
            page=page,
            page_size=page_size,
            source_options=SOURCE_OPTIONS,
        )

    def get_item(self, item_id: str) -> ThreatFeedItem | None:
        return self.storage.get_item(item_id)

    def sources(self) -> tuple[FeedSourceStatus, ...]:
        known = {source.id: source for source in self.storage.list_sources()}
        return tuple(
            known.get(
                item.id,
                FeedSourceStatus(
                    id=item.id,
                    name=item.name,
                    kind=item.kind,
                ),
            )
            for item in (*SOURCES, SourceDefinition("nvd", "NVD", "json", "https://nvd.nist.gov"))
        )

    def summary(self) -> FeedSummary:
        from .queries import database_backed, home_page

        if database_backed(self.storage):
            return home_page(
                self.storage, query=None, topic=None, hours=None, limit_per_region=0, sort="newest"
            ).summary
        items = self.storage.list_items()
        recent_cutoff = datetime.now(UTC) - timedelta(hours=24)
        regions = {
            region: RegionCount(
                total=sum(item.region == region for item in items),
                recent=sum(
                    item.region == region and item.published_at >= recent_cutoff for item in items
                ),
            )
            for region in FeedRegion
        }
        refreshed = self._timestamp("last_refresh")
        return FeedSummary(
            regions=regions,
            critical=sum(item.severity == "critical" for item in items),
            new_iocs=sum(
                len(item.entities) for item in items if item.published_at >= recent_cutoff
            ),
            last_refreshed_at=refreshed,
            next_refresh_at=refreshed + PUBLIC_REFRESH_COOLDOWN if refreshed else None,
            source_errors=sum(source.last_error_code is not None for source in self.sources()),
        )

    def _timestamp(self, key: str) -> datetime | None:
        value = self.storage.state(key)
        return datetime.fromisoformat(value) if value else None
