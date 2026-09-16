from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.api.routes.threat_feed import get_threat_feed_service, router
from threatlens.threat_feed.logic import classify_region, classify_topic, deterministic_summary
from threatlens.threat_feed.models import FeedRegion, FeedTopic, SourceEntry, ThreatFeedItem
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.sources import parse_rss
from threatlens.threat_feed.storage import FeedStorage


def entry(title: str, excerpt: str = "") -> SourceEntry:
    return SourceEntry(
        title=title,
        excerpt=excerpt,
        url="https://example.test/report",
        published_at=datetime(2026, 9, 16, tzinfo=UTC),
    )


def test_malaysia_takes_precedence_over_southeast_asia() -> None:
    item = entry("Malaysia and Singapore issue joint cyber advisory")
    region, relevance, reasons = classify_region("global", item)
    assert region == FeedRegion.MALAYSIA
    assert relevance == "medium"
    assert reasons


def test_topic_and_summary_are_deterministic() -> None:
    item = entry("CVE-2026-1234 actively exploited", "Apply the vendor update immediately.")
    topic = classify_topic(item)
    assert topic == FeedTopic.ACTIVE_EXPLOITATION
    assert deterministic_summary(item, topic) == deterministic_summary(item, topic)


def test_atom_parser_preserves_source_metadata() -> None:
    payload = """<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>one</id>
    <title>Security advisory for Example</title><summary>Install the update.</summary>
    <link href="https://example.test/one"/><updated>2026-09-16T10:00:00Z</updated>
    </entry></feed>"""
    parsed = parse_rss(payload.encode())
    assert len(parsed) == 1
    assert parsed[0].guid == "one"
    assert parsed[0].url == "https://example.test/one"


def feed_item(item_id: str, region: FeedRegion, published_at: datetime) -> ThreatFeedItem:
    return ThreatFeedItem.model_validate(
        {
            "id": item_id,
            "source_id": "test",
            "source_name": "Test Source",
            "source_kind": "rss",
            "title": f"Report {item_id}",
            "summary": "A deterministic test report.",
            "url": f"https://example.test/{item_id}",
            "published_at": published_at,
            "collected_at": published_at,
            "region": region,
            "relevance": "general",
            "topic": "advisory",
        }
    )


def test_home_combines_regions_from_one_snapshot(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    storage = FeedStorage()
    now = datetime.now(UTC)
    storage.save_items(
        [
            feed_item("global", FeedRegion.GLOBAL, now),
            feed_item("malaysia", FeedRegion.MALAYSIA, now),
        ]
    )
    storage.set_state("last_refresh", now.isoformat())
    service = ThreatFeedService(storage)

    result = service.home(hours=24, limit_per_region=5)

    assert result.sections[FeedRegion.GLOBAL].total == 1
    assert result.sections[FeedRegion.MALAYSIA].items[0].id == "malaysia"
    assert result.summary.regions[FeedRegion.SOUTHEAST_ASIA].total == 0
    assert service.home(hours=24, limit_per_region=5) is result


def test_home_endpoint_sets_cache_headers_and_honors_etag(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    service = ThreatFeedService(FeedStorage())
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_threat_feed_service] = lambda: service
    client = TestClient(app)

    first = client.get("/api/v1/threat-feed/home?hours=168")
    second = client.get(
        "/api/v1/threat-feed/home?hours=168",
        headers={"If-None-Match": first.headers["etag"]},
    )

    assert first.status_code == 200
    assert first.headers["cache-control"] == "public, s-maxage=300, stale-while-revalidate=3600"
    assert second.status_code == 304
