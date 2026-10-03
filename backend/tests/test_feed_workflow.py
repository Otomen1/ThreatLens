from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import HttpUrl

from threatlens.api.routes.threat_feed import get_threat_feed_service, router
from threatlens.ioc_feed.models import IocReport
from threatlens.ioc_feed.parsers import normalize
from threatlens.ioc_feed.storage import get_storage
from threatlens.threat_feed.evidence import explicit_cves, targeting
from threatlens.threat_feed.models import (
    FeedEntity,
    FeedRegion,
    FeedSourceStatus,
    FeedTopic,
    ThreatFeedItem,
)
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage
from threatlens.threat_feed.workflow import (
    canonical_url,
    clear_workflow_cache,
    coverage,
    related,
    search,
)


@pytest.fixture(params=["memory", "sqlite"])
def storage(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "workflow.db"))
    monkeypatch.delenv("VERCEL", raising=False)
    return FeedStorage()


def report():
    return IocReport(
        id="ioc-one",
        vendor="talos",
        title="Example report",
        path="iocs.txt",
        source_url="https://github.com/Cisco-Talos/IOCs/blob/main/iocs.txt",
        article_url="https://example.test/report",
        activity_at=datetime.now(UTC),
        collected_at=datetime.now(UTC),
        commit="a" * 40,
        blob="b" * 40,
        license="CC0-1.0",
        license_url="https://example.test/license",
        attribution="Cisco Talos",
        cves=("CVE-2026-1234",),
    )


def news():
    return ThreatFeedItem(
        id="news-one",
        source_id="talos",
        source_name="Talos",
        source_kind="rss",
        title="Example report",
        excerpt="A source report",
        summary="A source report",
        url=HttpUrl("https://example.test/report/"),
        published_at=datetime.now(UTC),
        collected_at=datetime.now(UTC),
        region=FeedRegion.GLOBAL,
        relevance="general",
        topic=FeedTopic.RESEARCH,
        entities=(FeedEntity(type="cve", value="CVE-2026-1234", normalized_value="CVE-2026-1234"),),
    )


def test_exact_search_and_related_metadata(storage):
    storage.save_items([news()])
    db = get_storage(storage)
    indicator = normalize("evil.test")
    assert indicator
    db.save(report(), (indicator,), {})
    result = search(storage, " cve-2026-1234 ", {})
    assert result.groups["news"].total == result.groups["ioc"].total == 1
    assert result.poc_cve == "CVE-2026-1234"
    assert search(storage, "evil[.]test", {}).groups["ioc"].total == 1
    assert search(storage, "CVE-2026-12345", {}).groups["ioc"].total == 0
    found = related(storage, "news", "news-one")
    assert found and found.items[0].reason == "References the same CVE"
    assert not found.items[0].record.indicators
    assert related(storage, "news", "missing") is None
    other = news().model_copy(
        update={"id": "other", "url": HttpUrl("https://elsewhere.test/"), "entities": ()}
    )
    storage.save_items([other])
    assert related(storage, "news", "other").items == ()


def test_cve_mentions_sorting_and_cache_invalidation(storage):
    old = news().model_copy(
        update={
            "title": "Report for CVE-2026-1234",
            "entities": (),
            "published_at": datetime.now(UTC) - timedelta(days=1),
        }
    )
    new = old.model_copy(update={"id": "new", "published_at": datetime.now(UTC)})
    storage.save_items([old, new])
    assert search(storage, "CVE-2026-1234", {}).groups["news"].total == 2
    assert search(storage, "CVE-2026-1234", {}, True).groups["news"].items[0].id == old.id
    storage.save_items([old.model_copy(update={"id": "third"})])
    assert search(storage, "CVE-2026-1234", {}).groups["news"].total == 2
    clear_workflow_cache()
    assert search(storage, "CVE-2026-1234", {}).groups["news"].total == 3


def test_history_budget_and_retention_preserve_current(storage, monkeypatch):
    db = get_storage(storage)
    first, second = normalize("evil.test"), normalize("changed.test")
    assert first and second
    original = report()
    db.save(original, (first,), {})
    monkeypatch.setattr("threatlens.ioc_feed.history.MAX_HISTORY_BYTES", 1)
    monkeypatch.setattr("threatlens.ioc_feed.storage.MAX_HISTORY_BYTES", 1)
    db.save(original.model_copy(update={"commit": "c" * 40}), (second,), {})
    assert db.changes(original.id)["total"] == 0 and db.changes(original.id)["limited"]
    assert db.detail(original.id)[1] == (second,)


def test_history_baseline_changes_idempotence_and_limit(storage):
    db = get_storage(storage)
    first, second = normalize("evil.test"), normalize("changed.test")
    assert first and second
    original = report()
    db.save(original, (first,), {})
    assert db.changes(original.id)["total"] == 0
    updated = original.model_copy(update={"commit": "c" * 40})
    db.save(updated, (second,), {"test-cursor": "advanced"})
    change = db.changes(original.id)["items"][0]
    assert change.added == (second,) and change.removed == (first,)
    db.save(updated, (second,), {})
    assert db.changes(original.id)["total"] == 1
    for i in range(12):
        item = normalize(f"example-{i}.test")
        assert item
        db.save(
            original.model_copy(update={"commit": f"{i:040x}", "collected_at": datetime.now(UTC)}),
            (item,),
            {},
        )
    assert db.changes(original.id)["total"] == 10
    assert db.changes(original.id)["limited"]
    assert db.detail(original.id) and storage.state("test-cursor") == "advanced"


def test_sqlite_revision_failure_rolls_back(storage, monkeypatch):
    if storage.backend != "sqlite":
        return
    db = get_storage(storage)
    first, second = normalize("evil.test"), normalize("changed.test")
    assert first and second
    db.save(report(), (first,), {})

    def fail(*args):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr("threatlens.ioc_feed.storage.maintain", fail)
    with pytest.raises(RuntimeError):
        db.save(report(), (second,), {"cursor": "advanced"})
    assert db.detail("ioc-one")[1] == (first,) and storage.state("cursor") is None


def test_public_workflow_api_limits(storage):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_threat_feed_service] = lambda: ThreatFeedService(storage)
    client = TestClient(app)
    assert client.get("/api/v1/threat-feed/status").status_code == 200
    assert client.get("/api/v1/threat-feed/search?q=example").status_code == 200
    assert client.get("/api/v1/threat-feed/search?q=example&news_page=0").status_code == 422
    assert client.get("/api/v1/threat-feed/related/news/missing").status_code == 404


def test_explicit_cves_and_targeting_only():
    assert canonical_url("https://example.test/story/?id=1&utm_source=x") == (
        "https://example.test/story?id=1"
    )
    assert canonical_url("https://example.test/") == ""
    assert canonical_url("https://example.test/story?id=2") != (
        canonical_url("https://example.test/story?id=1")
    )
    assert explicit_cves(
        b'{"cves":["CVE-2026-1234"],"description":"CVE-2026-9999"}', "iocs.json"
    ) == ("CVE-2026-1234",)
    assert explicit_cves(b"Reference mentions CVE-2026-9999\nCVE: CVE-2026-1234", "iocs.txt") == (
        "CVE-2026-1234",
    )
    assert not targeting("MyCERT", {"title": "A Malaysian research report about evil.my"})
    assert not targeting("Talos", {"title": "No evidence of attacks on Malaysia"})
    assert targeting("Talos", {"title": "Phishing targets Malaysian banks"})[0].region == "malaysia"
    assert targeting("Talos", {"excerpt": "Malware affects Singapore users"}, related_report=True)[
        0
    ].related_report


def test_coverage_stale_and_missing(monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    monkeypatch.delenv("VERCEL", raising=False)
    storage = FeedStorage()
    now = datetime.now(UTC)
    storage.save_source(
        FeedSourceStatus(
            id="mycert",
            name="MyCERT",
            kind="rss",
            last_success_at=now - timedelta(hours=9),
            last_attempt_at=now,
            last_error="The source could not be refreshed safely.",
        )
    )
    storage.set_state("last_refresh_attempt", now.isoformat())
    result = coverage(storage, now)
    source = next(s for s in result.sources if s.id == "mycert")
    assert source.stale and source.state == "failed" and source.last_attempt_at == now
    assert result.next_refresh_at == now + timedelta(minutes=30)
    assert next(s for s in result.sources if s.id == "nvd").state == "never_checked"
    assert next(s for s in result.sources if s.id == "sophoslabs").state == "disabled"


def test_eight_hour_boundary_and_partial(monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    monkeypatch.delenv("VERCEL", raising=False)
    storage = FeedStorage()
    now = datetime.now(UTC)
    storage.set_state("nvd_last_success", (now - timedelta(hours=8)).isoformat())
    storage.set_state("nvd_status", "partial")
    storage.set_state("nvd_pending", "{}")
    nvd = next(s for s in coverage(storage, now).sources if s.id == "nvd")
    assert not nvd.stale and nvd.state == "partial" and nvd.pending == 1
