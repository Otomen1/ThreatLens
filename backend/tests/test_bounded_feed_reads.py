"""Counts/order parity and bounded deserialization on the public database reads."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from threatlens.threat_feed.models import FeedRegion, FeedTopic, ThreatFeedItem
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage
from threatlens.threat_feed.workflow import search


def items():
    now = datetime.now(UTC)
    return [
        ThreatFeedItem(
            id=f"row-{i:03}",
            source_id="test",
            source_name="Test",
            source_kind="rss",
            title=f"Report CVE-2026-1234 {i}",
            summary="Stored metadata",
            url=f"https://example.test/{i}",
            published_at=now - timedelta(minutes=i),
            collected_at=now,
            region=list(FeedRegion)[i % 3],
            relevance="general",
            region_reasons=(),
            topic=FeedTopic.VULNERABILITY,
            entities=(),
        )
        for i in range(120)
    ]


def test_home_and_pages_match_memory_without_loading_whole_collections(tmp_path, monkeypatch):
    source = items()
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    memory = FeedStorage()
    memory.save_items(source)
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "feed.db"))
    database = FeedStorage()
    database.save_items(source)
    expected = ThreatFeedService(memory)
    actual = ThreatFeedService(database)
    database.list_items = lambda: (_ for _ in ()).throw(AssertionError("Full collection read"))
    database.list_vulnerabilities = lambda: (_ for _ in ()).throw(
        AssertionError("Full vulnerability read")
    )
    with patch.object(
        ThreatFeedItem, "model_validate_json", wraps=ThreatFeedItem.model_validate_json
    ) as hydrate:
        response = actual.home(limit_per_region=5)
        assert hydrate.call_count == 15
    baseline = expected.home(limit_per_region=5)
    assert response.summary == baseline.summary
    assert response.sections == baseline.sections
    for sort in ("newest", "oldest"):
        for region in FeedRegion:
            assert actual.list_items(
                region=region, page=2, page_size=7, sort=sort
            ) == expected.list_items(region=region, page=2, page_size=7, sort=sort)
    found = search(database, "cve-2026-1234", {"news": 2, "vulnerability": 1, "ioc": 1})
    assert found.groups["news"].total == 120 and len(found.groups["news"].items) == 20
    assert found.groups["vulnerability"].total == 1
