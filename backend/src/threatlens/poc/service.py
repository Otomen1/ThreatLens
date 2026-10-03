"""Bounded online lookup, per-source coalescing and stale metadata fallback."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import httpx

from ..threat_feed.storage import FeedStorage
from .adapters import MetadataIndex, download_index
from .models import Source, SourceResult, Status

logger = logging.getLogger("threatlens.poc")


@dataclass(frozen=True)
class CachedIndex:
    index: MetadataIndex
    checked_at: datetime


class PocService:
    def __init__(self, storage: FeedStorage) -> None:
        self.storage = storage
        self.cache: dict[Source, CachedIndex] = {}
        self.locks = {source: asyncio.Lock() for source in ("metasploit", "nuclei")}

    def result(
        self,
        source: Source,
        cve: str,
        *,
        failure: Status | None = None,
        code: str | None = None,
        next_at: datetime | None = None,
        cached: bool = True,
    ) -> SourceResult:
        now = datetime.now(UTC)
        entry = self.cache.get(source)
        age = max(0, int((now - entry.checked_at).total_seconds())) if entry else None
        if age is not None and age >= 86400:
            self.cache.pop(source, None)
            entry, age = None, None
        matches = tuple(r for r in entry.index.records if cve in r.cves) if entry else ()
        status: Status = failure or ("completed" if matches else "no_matches")
        messages: dict[Status, str] = {
            "completed": "CVE reference confirmed; resources are not locally tested.",
            "no_matches": "No exact matches in the successfully checked source.",
            "timed_out": "Source lookup timed out.",
            "rate_limited": "Source lookup is cooling down or rate-limited.",
            "busy": "Another source lookup is already running.",
            "unavailable": "Source metadata is temporarily unavailable.",
        }
        return SourceResult(
            source=source,
            cve=cve,
            status=status,
            matches=matches[:100],
            total_matches=len(matches),
            truncated=len(matches) > 100,
            checked_at=entry.checked_at if entry else now,
            cached=cached and entry is not None,
            cache_age_seconds=age,
            stale=bool(failure and entry),
            error_code=code,
            message=messages[status],
            retryable=failure is not None,
            next_eligible_at=next_at,
            skipped_records=entry.index.skipped if entry else 0,
        )

    async def lookup(self, source: Source, cve: str, *, refresh: bool = False) -> SourceResult:
        previous = self.cache.get(source)
        next_at: datetime | None = None
        try:
            async with asyncio.timeout(20):
                async with self.locks[source]:
                    entry = self.cache.get(source)
                    # A concurrently completed refresh satisfies waiting force-refresh calls too.
                    if (
                        entry
                        and (not refresh or entry is not previous)
                        and (datetime.now(UTC) - entry.checked_at).total_seconds() < 3600
                    ):
                        return self.result(source, cve)
                    owner = str(uuid4())
                    acquired, busy, next_at = await asyncio.to_thread(
                        self.storage.reserve_poc_source, source, owner, datetime.now(UTC)
                    )
                    if not acquired:
                        return self.result(
                            source,
                            cve,
                            failure="busy" if busy else "rate_limited",
                            code="source_busy" if busy else "source_cooldown",
                            next_at=next_at,
                        )
                    try:
                        index = await download_index(source)
                        self.cache[source] = CachedIndex(index, datetime.now(UTC))
                    finally:
                        await asyncio.to_thread(
                            self.storage.reserve_poc_source,
                            source,
                            owner,
                            datetime.now(UTC),
                            release=True,
                        )
                    return self.result(source, cve, cached=False)
        except (TimeoutError, httpx.TimeoutException):
            return self.result(
                source, cve, failure="timed_out", code="source_timeout", next_at=next_at
            )
        except httpx.HTTPStatusError as error:
            limited = error.response.status_code == 429
            logger.warning(
                "PoC source HTTP failure: source=%s status=%s", source, error.response.status_code
            )
            return self.result(
                source,
                cve,
                failure="rate_limited" if limited else "unavailable",
                code="upstream_rate_limit" if limited else "upstream_unavailable",
                next_at=next_at,
            )
        except Exception:
            # Never log payloads, metadata descriptions, exception text, or request tokens.
            logger.error("PoC metadata lookup failed: source=%s", source)
            return self.result(
                source, cve, failure="unavailable", code="source_unavailable", next_at=next_at
            )
