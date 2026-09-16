"""Public read and bounded refresh endpoints for the Threat Feed."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Annotated, Any

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
    ThreatFeedItem,
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


@router.get("/home", response_model=FeedHomeResponse)
def home(
    request: Request,
    response: Response,
    service: Annotated[ThreatFeedService, Depends(get_threat_feed_service)],
    topic: FeedTopic | None = None,
    hours: Annotated[int | None, Query(ge=1, le=720)] = None,
    query: Annotated[str | None, Query(max_length=200)] = None,
    limit_per_region: Annotated[int, Query(ge=1, le=20)] = 5,
) -> Any:
    result = service.home(
        query=query,
        topic=topic,
        hours=hours,
        limit_per_region=limit_per_region,
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
) -> FeedListResponse:
    return service.list_items(
        region=region,
        source=source,
        topic=topic,
        hours=hours,
        query=query,
        page=page,
        page_size=page_size,
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
