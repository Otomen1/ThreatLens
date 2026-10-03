"""Public read and bounded refresh endpoints for the Threat Feed."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response

from ...threat_feed import FeedStorage, ThreatFeedService
from ...threat_feed.models import (
    FeedHomeResponse,
    FeedListResponse,
    FeedRefreshResult,
    FeedRegion,
    FeedSourceStatus,
    FeedSummary,
    FeedTopic,
    FeedVulnerability,
    ThreatFeedItem,
    VulnerabilityListResponse,
)
from ...threat_feed.vulnerabilities import link_reports
from ...threat_feed.workflow import (
    FeedCoverage,
    FeedRelated,
    FeedSearch,
    RecordKind,
    coverage,
    related,
    search,
)

router = APIRouter(prefix="/api/v1/threat-feed", tags=["threat-feed"])
_service: ThreatFeedService | None = None


def get_threat_feed_service() -> ThreatFeedService:
    global _service
    if _service is None:
        _service = ThreatFeedService(FeedStorage())
    return _service


@router.get("/summary", response_model=FeedSummary)
def summary(service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)]) -> FeedSummary:
    return service.summary()


@router.get("/status", response_model=FeedCoverage)
def feed_status(
    response: Response,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
) -> FeedCoverage:
    response.headers["Cache-Control"] = "public, s-maxage=300, stale-while-revalidate=3600"
    return coverage(service.storage)


@router.get("/search", response_model=FeedSearch)
def search_feed(
    response: Response,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
    q: Annotated[str, Query(min_length=1, max_length=200)],
    news_page: Annotated[int, Query(ge=1, le=10000)] = 1,
    vulnerability_page: Annotated[int, Query(ge=1, le=10000)] = 1,
    ioc_page: Annotated[int, Query(ge=1, le=10000)] = 1,
    sort: Literal["newest", "oldest"] = "newest",
) -> FeedSearch:
    response.headers["Cache-Control"] = "public, s-maxage=300, stale-while-revalidate=3600"
    return search(
        service.storage,
        q,
        {"news": news_page, "vulnerability": vulnerability_page, "ioc": ioc_page},
        sort == "oldest",
    )


@router.get("/related/{kind}/{record_id}", response_model=FeedRelated)
def related_feed(
    kind: RecordKind,
    record_id: str,
    response: Response,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
) -> FeedRelated:
    result = related(service.storage, kind, record_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Feed record not found")
    response.headers["Cache-Control"] = "public, s-maxage=300, stale-while-revalidate=3600"
    return result


@router.get("/home", response_model=FeedHomeResponse)
def home(
    request: Request,
    response: Response,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
    topic: FeedTopic | None = None,
    hours: Annotated[int | None, Query(ge=1, le=720)] = None,
    query: Annotated[str | None, Query(max_length=200)] = None,
    limit_per_region: Annotated[int, Query(ge=1, le=20)] = 5,
    sort: Literal["newest", "oldest"] = "newest",
) -> Any:
    result = service.home(
        query=query,
        topic=topic,
        hours=hours,
        limit_per_region=limit_per_region,
        sort=sort,
    )
    identity = json.dumps(
        {
            "refresh": result.summary.last_refreshed_at.isoformat()
            if result.summary.last_refreshed_at
            else "",
            "query": (query or "").strip().lower(),
            "topic": topic.value if topic else "",
            "hours": hours,
            "limit": limit_per_region,
            "sort": sort,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    etag = f'"{hashlib.sha256(identity.encode()).hexdigest()}"'
    cache_control = "public, s-maxage=300, stale-while-revalidate=3600"
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": cache_control})
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = cache_control
    return result


@router.get("/items", response_model=FeedListResponse)
def list_items(
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
    region: FeedRegion | None = None,
    source: str | None = None,
    topic: FeedTopic | None = None,
    hours: Annotated[int | None, Query(ge=1, le=720)] = None,
    query: Annotated[str | None, Query(max_length=200)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    sort: Literal["newest", "oldest"] = "newest",
) -> FeedListResponse:
    return service.list_items(
        region=region,
        source=source,
        topic=topic,
        hours=hours,
        query=query,
        page=page,
        page_size=page_size,
        sort=sort,
    )


@router.get("/items/{item_id}", response_model=ThreatFeedItem)
def get_item(
    item_id: str, service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)]
) -> ThreatFeedItem:
    item = service.get_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Threat feed item not found")
    return item


@router.get("/sources", response_model=tuple[FeedSourceStatus, ...])
def sources(
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
) -> tuple[FeedSourceStatus, ...]:
    return service.sources()


@router.get("/vulnerabilities", response_model=VulnerabilityListResponse)
def vulnerabilities(
    response: Response,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
    category: Literal["all", "new_cves", "zero_days", "known_exploited"] = "all",
    severity: Literal["", "critical", "high", "medium", "low"] = "",
    source: Annotated[str, Query(max_length=150)] = "",
    query: Annotated[str, Query(max_length=200)] = "",
    hours: Annotated[int, Query(ge=1, le=720)] = 168,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    sort: Literal["newest", "oldest"] = "newest",
) -> VulnerabilityListResponse:
    response.headers["Cache-Control"] = "public, s-maxage=300, stale-while-revalidate=3600"
    return service.vulnerabilities(
        category=category,
        severity=severity,
        source=source,
        query=query,
        hours=hours,
        page=page,
        page_size=page_size,
        sort=sort,
    )


@router.get("/vulnerabilities/{record_id}", response_model=FeedVulnerability)
def vulnerability_detail(
    record_id: str,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
) -> FeedVulnerability:
    records = link_reports(
        service.storage.list_vulnerabilities(), service.storage.list_items(), datetime.now(UTC)
    )
    record = next((item for item in records if item.id == record_id.upper()), None)
    if record is None:
        record = next((item for item in records if item.id == record_id), None)
    if record is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return record


@router.post("/refresh", response_model=FeedRefreshResult)
async def refresh(
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
) -> FeedRefreshResult:
    return await service.refresh(force=False)


@router.post("/refresh/scheduled", response_model=FeedRefreshResult)
async def scheduled_refresh(
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
    authorization: Annotated[str | None, Header()] = None,
) -> FeedRefreshResult:
    secret = os.getenv("THREAT_FEED_CRON_SECRET", "")
    expected = f"Bearer {secret}"
    if not secret or not hmac.compare_digest(authorization or "", expected):
        raise HTTPException(status_code=401, detail="Invalid scheduled refresh credential")
    return await service.refresh(force=True)
