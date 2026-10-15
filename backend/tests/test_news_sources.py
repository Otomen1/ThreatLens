from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from threatlens.threat_feed import service as module
from threatlens.threat_feed.logic import stable_id
from threatlens.threat_feed.models import FeedRegion
from threatlens.threat_feed.sources import MAX_ITEMS, SOURCES, fetch_source, parse_rss
from threatlens.threat_feed.storage import FeedStorage

FIXTURES = Path(__file__).parent / "fixtures" / "news_sources"


@pytest.mark.parametrize("name", ["ahnlab", "fortinet", "eset"])
def test_publisher_rss_preserves_dates_attribution_and_guid(name):
    source = next(source for source in SOURCES if source.id == name)
    entries = parse_rss((FIXTURES / f"{name}.xml").read_bytes())
    assert source.kind == "rss" and len(entries) == 1
    entry = entries[0]
    assert entry.published_at == datetime(2026, 10, 14, 8, tzinfo=UTC)
    assert entry.guid and entry.categories and "<p>" not in entry.excerpt
    assert stable_id(source.id, entry) == stable_id(source.id, entry)
    if name == "fortinet":
        assert entry.url == "https://www.fortinet.com/blog/threat-research/synthetic-report"


def test_unsafe_original_link_does_not_replace_publisher_link():
    payload = (FIXTURES / "fortinet.xml").read_text()
    for unsafe in ("javascript:alert(1)", "https://user:password@example.test/", "https://[broken"):
        changed = payload.replace(
            "<feedburner:origLink>https://www.fortinet.com/blog/threat-research/synthetic-report</feedburner:origLink>",
            f"<feedburner:origLink>{unsafe}</feedburner:origLink>",
        )
        assert parse_rss(changed.encode())[0].url.startswith("https://feeds.fortinet.com/")


def test_rss_item_cap_still_applies():
    item = "<item><title>Synthetic report</title><link>https://example.test/report</link></item>"
    assert len(parse_rss(f"<rss><channel>{item * 100}</channel></rss>".encode())) == MAX_ITEMS


@pytest.mark.asyncio
async def test_fetch_only_requests_the_configured_feed(monkeypatch):
    original = httpx.AsyncClient
    calls = []

    def respond(request):
        calls.append(str(request.url))
        return httpx.Response(200, content=(FIXTURES / "fortinet.xml").read_bytes())

    monkeypatch.setattr(
        "threatlens.threat_feed.sources.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(respond), **kwargs),
    )
    source = next(source for source in SOURCES if source.id == "fortinet")
    assert len(await fetch_source(source)) == 1
    assert calls == [source.url]


@pytest.mark.asyncio
async def test_repeat_collection_deduplicates_and_preserves_healthy_sources(monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    now = datetime.now(UTC)
    chosen = tuple(source for source in SOURCES if source.id in {"ahnlab", "fortinet", "eset"})
    failed = False

    async def fetch(source):
        if failed and source.id == "fortinet":
            raise httpx.ReadTimeout("Synthetic upstream failure")
        return tuple(
            entry.model_copy(update={"published_at": now})
            for entry in parse_rss((FIXTURES / f"{source.id}.xml").read_bytes())
        )

    monkeypatch.setattr(module, "SOURCES", chosen)
    monkeypatch.setattr(module, "fetch_source", fetch)
    monkeypatch.setattr(module, "sync_nvd", AsyncMock())
    service = module.ThreatFeedService(FeedStorage())
    first = await service.refresh(force=True)
    second = await service.refresh(force=True)
    assert first.items_added == 3 and second.items_added == 0
    failed = True
    third = await service.refresh(force=True)
    assert third.sources_succeeded == 3  # Two healthy feeds plus the mocked NVD sync.
    assert len(service.storage.list_items()) == 3
    assert {row.source_id for row in service.storage.list_items()} == {"ahnlab", "fortinet", "eset"}
    assert (
        next(row for row in service.storage.list_items() if row.source_id == "ahnlab").region
        == FeedRegion.MALAYSIA
    )
    status = next(source for source in service.sources() if source.id == "fortinet")
    assert status.last_error_code == "timeout" and status.last_success_at is not None
