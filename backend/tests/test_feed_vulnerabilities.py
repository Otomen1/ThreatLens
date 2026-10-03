from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.api.routes.threat_feed import get_threat_feed_service, router
from threatlens.threat_feed.models import FeedRegion, FeedTopic, ThreatFeedItem
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage
from threatlens.threat_feed.vulnerabilities import (
    link_reports,
    parse_nvd,
    sync_nvd,
    vulnerability_list,
)


@pytest.fixture(params=["memory", "sqlite"])
def storage(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "feed.db"))
    return FeedStorage()


def cve(now, cve_id="CVE-2026-12345"):
    return {
        "id": cve_id,
        "published": now.isoformat(),
        "lastModified": now.isoformat(),
        "descriptions": [{"lang": "en", "value": "Example product vulnerability"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"},
                }
            ]
        },
    }


def report(now, title="CVE-2026-12345 zero-day exploited", source="publisher", item_id="one"):
    return ThreatFeedItem(
        id=item_id,
        source_id=source,
        source_name=source,
        source_kind="rss",
        title=title,
        summary=title,
        excerpt="Install the vendor update.",
        url=f"https://example.test/{item_id}",
        published_at=now,
        collected_at=now,
        region=FeedRegion.GLOBAL,
        relevance="general",
        topic=FeedTopic.VULNERABILITY,
    )


def test_official_and_multiple_cve_reports_group_without_inventing_zero_day():
    now = datetime.now(UTC)
    official = parse_nvd(cve(now), now)
    assert official is not None
    kev = report(now, "CVE-2026-12345 known exploited vulnerability", "cisa_kev")
    news = report(now, "CVE-2026-12345 and CVE-2026-54321 zero-day flaws", item_id="two")
    records = {record.id: record for record in link_reports([official], [kev, news], now)}
    main = records["CVE-2026-12345"]
    assert main.published_at == now
    assert main.scores[0].source == "nvd@nist.gov"
    assert main.known_exploited and main.reported_zero_day
    assert len(main.reports) == 2
    assert len(records["CVE-2026-54321"].reports) == 1
    assert not link_reports([], [kev], now)[0].reported_zero_day


def test_no_cve_no_scores_and_naive_nvd_dates():
    now = datetime.now(UTC)
    item = cve(now)
    item["published"] = now.replace(tzinfo=None).isoformat()
    item["metrics"] = {}
    record = parse_nvd(item, now)
    assert record and record.published_at.tzinfo == UTC
    assert record.severity is None and record.scores == ()
    records = link_reports([], [report(now, "Vendor reports a zero-day without CVE")], now)
    assert records[0].cve_id is None and records[0].reported_zero_day


def test_storage_filters_retention_and_lease(storage):
    now = datetime.now(UTC)
    item = parse_nvd(cve(now), now)
    assert item is not None
    storage.save_vulnerabilities([item], state={"nvd_cursor": now.isoformat()})
    assert storage.state("nvd_cursor") == now.isoformat()
    result = vulnerability_list(storage, category="new_cves", severity="critical")
    assert result.total == result.published_24h == 1
    assert vulnerability_list(storage, category="zero_days").total == 0
    assert storage.acquire_refresh("one", now, force=False)
    assert not storage.acquire_refresh("two", now, force=True)
    storage.release_refresh("two")
    assert not storage.acquire_refresh("three", now, force=True)
    storage.release_refresh("one")
    # Failed refresh attempts also consume the public cooldown.
    assert not storage.acquire_refresh("failed-retry", now, force=False)
    storage.set_state("last_refresh", now.isoformat())
    assert not storage.acquire_refresh("four", now, force=False)
    assert storage.acquire_refresh("five", now, force=True)
    storage.prune_vulnerabilities(now + timedelta(days=1))
    assert storage.list_vulnerabilities() == []


def test_sqlite_lease_is_shared_across_instances(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "shared.db"))
    first, second = FeedStorage(), FeedStorage()
    now = datetime.now(UTC)
    assert first.acquire_refresh("first", now, force=True)
    assert not second.acquire_refresh("second", now, force=True)
    first.release_refresh("first")
    assert not second.acquire_refresh("second", now, force=False)
    assert second.acquire_refresh("second", now, force=True)


@pytest.mark.asyncio
async def test_nvd_page_cap_spacing_cursor_and_resume(storage, monkeypatch):
    now = datetime.now(UTC)
    calls = []

    async def fetch(params):
        calls.append(params.copy())
        index = int(params["startIndex"])
        return {
            "vulnerabilities": [{"cve": cve(now, f"CVE-2026-{10000 + index}")}],
            "startIndex": index,
            "totalResults": 4,
        }

    sleep = AsyncMock()
    monkeypatch.setattr("threatlens.threat_feed.vulnerabilities.fetch_nvd_page", fetch)
    monkeypatch.setattr("threatlens.threat_feed.vulnerabilities.asyncio.sleep", sleep)
    await sync_nvd(storage, now)
    assert len(calls) == 3 and storage.state("nvd_status") == "partial"
    assert storage.state("nvd_cursor") is None
    assert [call.args for call in sleep.await_args_list] == [(6,), (6,)]
    await sync_nvd(storage, now)
    assert calls[-1]["startIndex"] == "3"
    assert storage.state("nvd_pending") == ""
    assert storage.state("nvd_cursor") == now.isoformat()
    assert len(storage.list_vulnerabilities()) == 4


@pytest.mark.asyncio
async def test_nvd_failure_does_not_advance_cursor(storage, monkeypatch):
    now = datetime.now(UTC)
    storage.set_state("nvd_cursor", (now - timedelta(days=1)).isoformat())
    original = storage.state("nvd_cursor")
    monkeypatch.setattr(
        "threatlens.threat_feed.vulnerabilities.fetch_nvd_page",
        AsyncMock(side_effect=TimeoutError("internal payload")),
    )
    with pytest.raises(TimeoutError):
        await sync_nvd(storage, now)
    assert storage.state("nvd_cursor") == original


@pytest.mark.asyncio
async def test_nvd_save_failure_and_rate_limit_keep_progress(storage, monkeypatch):
    now = datetime.now(UTC)
    payload = {"vulnerabilities": [{"cve": cve(now)}], "startIndex": 0, "totalResults": 1}
    monkeypatch.setattr(
        "threatlens.threat_feed.vulnerabilities.fetch_nvd_page", AsyncMock(return_value=payload)
    )

    def fail_save(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(storage, "save_vulnerabilities", fail_save)
    with pytest.raises(RuntimeError):
        await sync_nvd(storage, now)
    assert storage.state("nvd_cursor") is None
    assert storage.state("nvd_pending") is None
    assert storage.list_vulnerabilities() == []
    sleep = AsyncMock()
    monkeypatch.setattr("threatlens.threat_feed.vulnerabilities.asyncio.sleep", sleep)
    request = httpx.Request("GET", "https://services.nvd.nist.gov")
    response = httpx.Response(429, request=request)
    monkeypatch.setattr(
        "threatlens.threat_feed.vulnerabilities.fetch_nvd_page",
        AsyncMock(
            side_effect=httpx.HTTPStatusError("rate limited", request=request, response=response)
        ),
    )
    with pytest.raises(httpx.HTTPStatusError):
        await sync_nvd(storage, now)
    assert sleep.await_count == 1
    assert storage.state("nvd_cursor") is None


@pytest.mark.asyncio
async def test_refresh_keeps_news_when_nvd_fails(storage, monkeypatch):
    now = datetime.now(UTC)
    storage.save_items([report(now)])
    monkeypatch.setattr("threatlens.threat_feed.service.fetch_source", AsyncMock(return_value=()))
    monkeypatch.setattr(
        "threatlens.threat_feed.service.sync_nvd",
        AsyncMock(side_effect=TimeoutError("secret upstream detail")),
    )
    result = await ThreatFeedService(storage).refresh()
    assert result.status == "completed"
    assert result.errors == ("NVD: unavailable",)
    assert storage.get_item("one") is not None
    assert storage.state("nvd_status") == "delayed"
    assert "secret upstream detail" not in result.model_dump_json()


def test_public_api_pagination_and_cached_home_remain_compatible(storage):
    now = datetime.now(UTC)
    storage.save_items([report(now)])
    item = parse_nvd(cve(now), now)
    assert item is not None
    storage.save_vulnerabilities([item])
    service = ThreatFeedService(storage)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_threat_feed_service] = lambda: service
    client = TestClient(app)
    listing = client.get("/api/v1/threat-feed/vulnerabilities?category=zero_days&page_size=1")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.headers["cache-control"].startswith("public, s-maxage=300")
    assert client.get("/api/v1/threat-feed/vulnerabilities/CVE-2026-12345").status_code == 200
    assert client.get("/api/v1/threat-feed/vulnerabilities/missing").status_code == 404
    assert client.get("/api/v1/threat-feed/vulnerabilities?category=invalid").status_code == 422
    assert client.get("/api/v1/threat-feed/home").json()["sections"]["global"]["total"] == 1
