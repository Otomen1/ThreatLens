import asyncio
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from threatlens.ioc_feed.storage import IocStorage
from threatlens.threat_feed import service as module
from threatlens.threat_feed.logic import canonical_url, stable_id
from threatlens.threat_feed.models import FeedRegion, FeedTopic, ThreatFeedItem
from threatlens.threat_feed.queries import run
from threatlens.threat_feed.sources import (
    SOURCES,
    SourceDefinition,
    _date,
    fetch_source,
    parse_metadata_listing,
    parse_rss,
)
from threatlens.threat_feed.storage import FeedStorage


def test_official_rss_endpoints():
    urls = {source.id: source.url for source in SOURCES}
    assert urls["cisa"] == "https://cisa.gov/cybersecurity-advisories/all.xml"
    assert urls["mycert"] == "https://www.mycert.org.my/portal/rss"
    assert urls["singcert"].endswith("/advisories/rss.xml")


def test_mycert_dates_are_in_feed_descriptions_not_collection_time():
    payload = b"""<rss><channel><item><title>MyCERT Advisory - Synthetic threat</title>
    <description>Published date: 4 October 2026, 10:33 pm</description>
    <link>https://www.mycert.org.my/portal/details?menu=advisories&amp;id=one</link>
    <guid>source-one</guid></item></channel></rss>"""
    item = parse_rss(payload, source_id="mycert")[0]
    assert item.published_at == datetime(2026, 10, 4, 14, 33, tzinfo=UTC)
    assert "id=one" in canonical_url(item.url)
    assert canonical_url(item.url) != canonical_url(item.url.replace("id=one", "id=two"))
    assert not item.excerpt


def test_unknown_rss_dates_are_never_replaced_with_now():
    template = (
        "<rss><channel><item><title>Advisory</title>"
        "<link>https://example.test/one</link>{}</item></channel></rss>"
    )
    assert parse_rss(template.format("").encode()) == ()
    assert parse_rss(template.format("<pubDate>not a date</pubDate>").encode()) == ()
    assert _date("2026-10-04 14:33:00") == datetime(2026, 10, 4, 14, 33, tzinfo=UTC)
    assert _date("invalid") is None


def test_nc4_reads_real_card_fields_and_ignores_navigation_and_comments():
    card = """<a href="/alertAdvisory-detail/NC4-ALR-2026-000009" class="aa-card-link">
    <h5 class="card-id">NC4-ALR-2026-000009</h5><h4 class="card-title">Synthetic advisory</h4>
    <p class="card-para">An explicitly reported vulnerability.</p>
    <!-- <a href="/wrong">Nested commented link</a> -->
    <span>10 Oct 2026</span><span>View Details</span></a>"""
    navigation = '<a href="/alertAdvisory-detail/NC4-ALR-2026-000009">Learn More</a>'
    rows = parse_metadata_listing(navigation + card + card, "https://www.nc4.gov.my/alertAdvisory")
    assert len(rows) == 1
    assert rows[0].title == "Synthetic advisory"
    assert rows[0].excerpt == "An explicitly reported vulnerability."
    assert rows[0].published_at == datetime(2026, 10, 9, 16, tzinfo=UTC)
    assert not parse_metadata_listing(
        card.replace("10 Oct 2026", "Unknown"), "https://www.nc4.gov.my/alertAdvisory"
    )
    assert not parse_metadata_listing(
        card.replace("/alertAdvisory-detail/", "https://evil.test/"),
        "https://www.nc4.gov.my/alertAdvisory",
    )


@pytest.mark.asyncio
async def test_stream_size_limit_and_empty_metadata_are_failures(monkeypatch):
    original = httpx.AsyncClient
    from threatlens.threat_feed import sources

    payload = b"x" * 101
    monkeypatch.setattr(sources, "MAX_RESPONSE_BYTES", 100)
    monkeypatch.setattr(
        sources.httpx,
        "AsyncClient",
        lambda **kwargs: original(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=payload)),
            **kwargs,
        ),
    )
    with pytest.raises(ValueError, match="size limit"):
        await fetch_source(SOURCES[0])
    payload = b"<rss><channel/></rss>"
    with pytest.raises(ValueError, match="no dated report"):
        await fetch_source(next(source for source in SOURCES if source.id == "mycert"))


def test_every_feed_postgres_connection_disables_automatic_preparation(monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    store = FeedStorage()
    driver = MagicMock()
    store.psycopg = driver
    store.url = "postgresql://example.test/db"
    db = driver.connect.return_value.__enter__.return_value
    db.execute.return_value.fetchall.return_value = []
    store.list_sources()
    run(store, "SELECT 1 WHERE 1=?", [1])
    iocs = object.__new__(IocStorage)
    iocs.feed, iocs.pg = store, True
    with iocs.connection():
        pass
    assert driver.connect.call_count == 3
    for call in driver.connect.call_args_list:
        assert call.kwargs == {"prepare_threshold": None, "connect_timeout": 10}


@pytest.fixture(params=["memory", "sqlite"])
def store(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "feed.db"))
    return FeedStorage()


@pytest.mark.asyncio
async def test_old_listing_dates_are_repaired_without_changing_bookmark_ids(store, monkeypatch):
    now = datetime.now(UTC)
    published = now - timedelta(days=2)
    source = next(source for source in SOURCES if source.id == "singcert")
    from threatlens.threat_feed.models import SourceEntry

    entry = SourceEntry(
        guid="urn:official:new-guid",
        title="Updated advisory CVE-2026-1234",
        url="https://www.csa.gov.sg/alerts-and-advisories/advisories/example",
        published_at=published,
    )
    record_id = stable_id(source.id, entry.model_copy(update={"guid": None}))
    old = ThreatFeedItem(
        id=record_id,
        source_id=source.id,
        source_name=source.name,
        source_kind="metadata",
        title="Old listing card CVE-2026-1234",
        summary="Old summary",
        url=entry.url,
        published_at=now,
        collected_at=now,
        region=FeedRegion.SOUTHEAST_ASIA,
        relevance="high",
        topic=FeedTopic.ADVISORY,
    )
    store.save_items([old])
    from threatlens.threat_feed.models import VulnerabilityScore
    from threatlens.threat_feed.vulnerabilities import link_reports

    official = link_reports([], [old], now)[0].model_copy(
        update={
            "published_at": now - timedelta(days=10),
            "description": "Official CVE description",
            "sources": ("NVD", source.name),
            "products": ("Explicitly supplied product",),
            "scores": (VulnerabilityScore(source="NVD", version="3.1", score=7.5),),
        }
    )
    store.save_vulnerabilities([official])
    monkeypatch.setattr(module, "fetch_source", AsyncMock(return_value=(entry,)))
    service = module.ThreatFeedService(store)
    assert await service._collect(source, now) == (0, 1)
    saved = store.get_item(record_id)
    assert saved.published_at == published and saved.collected_at == old.collected_at
    assert saved.title == entry.title and saved.source_kind == "rss"
    vulnerability = next(r for r in store.list_vulnerabilities() if r.id == "CVE-2026-1234")
    assert vulnerability.activity_at == published
    assert vulnerability.reports[0].published_at == published
    assert vulnerability.description == official.description
    assert vulnerability.scores == official.scores and vulnerability.products == official.products
    assert service.home(hours=24).sections[FeedRegion.SOUTHEAST_ASIA].total == 0
    assert await service._collect(source, now) == (0, 1)


@pytest.mark.asyncio
async def test_refresh_keeps_http_concurrency_bounded_and_storage_off_event_loop(
    store, monkeypatch
):
    active = maximum = 0
    main_thread = threading.get_ident()
    chosen = tuple(
        SourceDefinition(f"test{i}", f"Source {i}", "rss", "https://example.test") for i in range(9)
    )

    async def fetch(source):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.001)
        active -= 1
        return ()

    service = module.ThreatFeedService(store)
    save = store.save_items

    def slow_save(items):
        assert threading.get_ident() != main_thread
        time.sleep(0.005)
        return save(items)

    monkeypatch.setattr(module, "SOURCES", chosen)
    monkeypatch.setattr(module, "fetch_source", fetch)
    monkeypatch.setattr(module, "sync_nvd", AsyncMock())
    monkeypatch.setattr(module, "collect_ioc_reports", AsyncMock())
    monkeypatch.setattr(store, "save_items", slow_save)
    response = await service.refresh(force=True)
    assert response.status == "completed" and 1 < maximum <= 4


@pytest.mark.asyncio
async def test_database_and_upstream_failures_have_distinct_safe_statuses(store, monkeypatch):
    source = SOURCES[0]
    monkeypatch.setattr(module, "SOURCES", (source,))
    monkeypatch.setattr(module, "fetch_source", AsyncMock(return_value=()))
    monkeypatch.setattr(module, "sync_nvd", AsyncMock())
    monkeypatch.setattr(module, "collect_ioc_reports", AsyncMock())
    monkeypatch.setattr(
        store, "save_items", MagicMock(side_effect=RuntimeError("secret database detail"))
    )
    service = module.ThreatFeedService(store)
    await service.refresh(force=True)
    assert service.sources()[0].last_error_code == "storage_error"
    assert "secret database detail" not in json.dumps(
        [s.model_dump(mode="json") for s in service.sources()]
    )
    error = httpx.HTTPStatusError(
        "private payload", request=httpx.Request("GET", source.url), response=httpx.Response(403)
    )
    service._source_error(source, datetime.now(UTC), error)
    assert service.sources()[0].last_error_code == "http_403"
