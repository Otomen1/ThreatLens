from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.api.routes.threat_feed import get_threat_feed_service, router
from threatlens.threat_feed.models import FeedRegion, FeedTopic, ThreatFeedItem
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.sources import SOURCE_OPTIONS
from threatlens.threat_feed.storage import FeedStorage


@pytest.fixture(params=["memory", "sqlite"])
def service(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "news.db"))
    storage = FeedStorage()
    now = datetime.now(UTC)
    storage.save_items(
        [
            ThreatFeedItem(
                id=f"{source}-{region.value}-{i}",
                source_id=source,
                source_name=source,
                source_kind="rss",
                title=f"Synthetic malware report {i}",
                summary="Stored metadata",
                url=f"https://example.test/{source}/{region.value}/{i}",
                published_at=now - timedelta(minutes=i),
                collected_at=now,
                region=region,
                relevance="general",
                topic=FeedTopic.MALWARE,
            )
            for source in ("ahnlab", "eset")
            for region in FeedRegion
            for i in range(12)
        ]
    )
    return ThreatFeedService(storage)


def test_source_filter_applies_to_home_regions_totals_and_caches(service):
    unfiltered = service.home(hours=24, limit_per_region=10)
    filtered = service.home(hours=24, source="ahnlab", limit_per_region=10)
    assert filtered.source_options == SOURCE_OPTIONS
    assert filtered.summary == unfiltered.summary  # Activity cards stay feed-wide.
    for region in FeedRegion:
        assert unfiltered.sections[region].total == 24
        assert filtered.sections[region].total == 12
        assert len(filtered.sections[region].items) == 10
        assert all(item.source_id == "ahnlab" for item in filtered.sections[region].items)
    assert service.home(hours=24, source="ahnlab", limit_per_region=10) is filtered
    assert service.home(hours=24, source="eset", limit_per_region=10) is not filtered
    assert service.home(source="missing").sections[FeedRegion.GLOBAL].total == 0


def test_regional_source_filter_stays_bounded_and_composes_with_other_filters(service):
    with patch.object(
        ThreatFeedItem, "model_validate_json", wraps=ThreatFeedItem.model_validate_json
    ) as hydrate:
        result = service.list_items(
            source="eset",
            region=FeedRegion.MALAYSIA,
            topic=FeedTopic.MALWARE,
            hours=24,
            query="synthetic",
            page=2,
            page_size=10,
        )
        if service.storage.backend == "sqlite":
            assert hydrate.call_count == 2
    assert result.total == 12 and len(result.items) == 2
    assert result.source_options == SOURCE_OPTIONS
    assert all(
        item.source_id == "eset" and item.region == FeedRegion.MALAYSIA for item in result.items
    )
    assert not service.list_items(source="' OR 1=1 --").items


def test_public_source_filter_etags_and_options_are_backward_compatible(service, monkeypatch):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_threat_feed_service] = lambda: service
    monkeypatch.setattr(
        "threatlens.threat_feed.service.fetch_source",
        lambda _: pytest.fail("No external collection"),
    )
    with TestClient(app) as client:
        first = client.get("/api/v1/threat-feed/home?source=ahnlab")
        other = client.get(
            "/api/v1/threat-feed/home?source=eset", headers={"If-None-Match": first.headers["etag"]}
        )
        assert first.status_code == other.status_code == 200
        assert first.headers["etag"] != other.headers["etag"]
        assert (
            client.get(
                "/api/v1/threat-feed/home?source=ahnlab",
                headers={"If-None-Match": first.headers["etag"]},
            ).status_code
            == 304
        )
        assert client.get("/api/v1/threat-feed/home").status_code == 200
        assert first.json()["source_options"] == [item.model_dump() for item in SOURCE_OPTIONS]
        assert client.get("/api/v1/threat-feed/home?source=" + "x" * 65).status_code == 422
