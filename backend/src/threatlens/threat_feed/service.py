"""Threat Feed collection and read service."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

import httpx
from pydantic import HttpUrl

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
    FeedListResponse,
    FeedRefreshResult,
    FeedRegion,
    FeedSourceStatus,
    FeedSummary,
    FeedTopic,
    RegionCount,
    ThreatFeedItem,
)
from .sources import SOURCES, SourceDefinition, fetch_source
from .storage import FeedStorage

RETENTION_DAYS = 30
PUBLIC_REFRESH_COOLDOWN = timedelta(minutes=30)
_logger = logging.getLogger("threatlens.threat_feed")


class ThreatFeedService:
    def __init__(self, storage: FeedStorage) -> None:
        self.storage = storage

    async def refresh(self, *, force: bool = False) -> FeedRefreshResult:
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
        results = await asyncio.gather(
            *(self._collect(source, now) for source in SOURCES), return_exceptions=True
        )
        added = seen = succeeded = 0
        errors: list[str] = []
        for source, result in zip(SOURCES, results, strict=True):
            if isinstance(result, BaseException):
                errors.append(f"{source.name}: unavailable")
                self._source_error(source, now, result)
                continue
            source_added, source_seen = result
            added += source_added
            seen += source_seen
            succeeded += 1
        if succeeded:
            self.storage.delete_before(now - timedelta(days=RETENTION_DAYS))
            self.storage.set_state("last_refresh", now.isoformat())
        completed = datetime.now(UTC)
        refresh = FeedRefreshResult(
            status="completed" if succeeded else "failed",
            started_at=now,
            completed_at=completed,
            sources_attempted=len(SOURCES),
            sources_succeeded=succeeded,
            items_added=added,
            items_seen=seen,
            errors=tuple(errors),
            next_refresh_at=now + PUBLIC_REFRESH_COOLDOWN,
        )
        self.storage.save_refresh(refresh)
        return refresh

    async def _collect(self, source: SourceDefinition, now: datetime) -> tuple[int, int]:
        entries = await fetch_source(source)
        items: list[ThreatFeedItem] = []
        cutoff = now - timedelta(days=RETENTION_DAYS)
        for entry in entries:
            if entry.published_at < cutoff:
                continue
            topic = classify_topic(entry)
            region, relevance, reasons = classify_region(source.id, entry)
            items.append(
                ThreatFeedItem(
                    id=stable_id(source.id, entry),
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
                )
            )
        added = self.storage.save_items(items)
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
            else "source_unavailable"
        )
        _logger.exception("Threat feed source refresh failed: %s", source.id, exc_info=error)
        previous = next(
            (item for item in self.storage.list_sources() if item.id == source.id), None
        )
        self.storage.save_source(
            FeedSourceStatus(
                id=source.id,
                name=source.name,
                kind=source.kind,
                last_success_at=previous.last_success_at if previous else None,
                last_attempt_at=now,
                last_error_code=code,
                last_error="The source could not be refreshed safely.",
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
    ) -> FeedListResponse:
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
        start = (page - 1) * page_size
        return FeedListResponse(
            items=tuple(filtered[start : start + page_size]),
            total=len(filtered),
            page=page,
            page_size=page_size,
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
            for item in SOURCES
        )

    def summary(self) -> FeedSummary:
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
