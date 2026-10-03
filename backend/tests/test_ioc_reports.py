import json
import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.api.routes import ioc_reports
from threatlens.ioc_feed.collector import (
    SOURCES,
    DownloadBudget,
    RateLimited,
    collect_source,
    statuses,
)
from threatlens.ioc_feed.models import IocReport
from threatlens.ioc_feed.parsers import (
    article_link,
    identity,
    normalize,
    parse_file,
    supported_path,
)
from threatlens.ioc_feed.service import clear_cache, listing
from threatlens.ioc_feed.storage import IocStorage, StorageCapacity
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage

NOW = datetime.now(UTC)
SHA = "a" * 40


@pytest.fixture(params=["memory", "sqlite"])
def db(request, tmp_path, monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "ioc.db"))
    clear_cache()
    return IocStorage(FeedStorage())


def report(id="one", vendor="talos", when=NOW):
    return IocReport(
        id=id,
        vendor=vendor,
        title="Example campaign",
        path="iocs.txt",
        source_url="https://github.com/Cisco-Talos/IOCs/blob/main/iocs.txt",
        activity_at=when,
        collected_at=NOW,
        commit=SHA,
        blob=SHA,
        license="CC0-1.0",
        license_url="https://github.com/Cisco-Talos/IOCs/blob/main/LICENSE",
        attribution="Cisco Talos; source-reported",
    )


@pytest.mark.parametrize(
    "value,kind,expected",
    [
        ("EXAMPLE[.]COM", "domain", "example.com"),
        ("hxxps://EXAMPLE[.]COM/Case?A=b", "url", "https://example.com/Case?A=b"),
        ("2001:db8::1", "ipv6", "2001:db8::1"),
        ("A" * 64, "sha256", "a" * 64),
    ],
)
def test_normalization(value, kind, expected):
    item = normalize(value, kind)
    assert item and item.value == expected and not item.verified


@pytest.mark.parametrize(
    "value",
    ["https://user:password@host.test/", "999.1.2.3", "a@b.com", "x.exe", "https://[bad", "a b"],
)
def test_invalid_and_sensitive_values(value):
    assert normalize(value) is None


def test_official_shapes_and_reference_exclusion():
    talos, _ = parse_file(
        "talos",
        "2026/iocs.txt",
        b"IOCs:\nexample[.]com\nReferences:\nhttps://publisher.test/report",
    )
    assert len(talos) == 1 and talos[0].type == "domain"
    unit, _ = parse_file(
        "unit42",
        "IOCs.txt",
        b"Report title\nhttps://unit42.paloaltonetworks.com/test\nIOCs:\nhxxps://bad[.]test/Path",
    )
    assert len(unit) == 1 and unit[0].type == "url"
    eset, _ = parse_file("eset", "campaign/samples.sha256", ("b" * 64 + "\n").encode())
    assert len(eset) == 1
    sophos, warnings = parse_file(
        "sophoslabs",
        "Campaign.csv",
        b"Indicator_type,Data,Note\ndomain,bad.test,C2\ndomain,bad.test,C2\nurl_path,/a,unsupported\n",
    )
    assert len(sophos) == 1 and warnings
    assert not SOURCES[-1].enabled
    assert article_link("unit42", b"https://unit42.paloaltonetworks.com/test")
    assert article_link("unit42", b"https://evil.test/test") is None


def test_markdown_tables_json_and_limits():
    stix = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.test']"},
            {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"},
            {"type": "indicator", "pattern": "[url:value LIKE '%evil%']"},
            {"type": "identity", "name": "https://publisher.test"},
        ],
    }
    stix_rows, stix_warnings = parse_file("talos", "iocs.json", json.dumps(stix).encode())
    assert len(stix_rows) == 2 and stix_warnings
    rows, _ = parse_file(
        "eset",
        "campaign/README.md",
        b"# Introduction\nhttps://publisher.test\n## IOCs\n|Type|Value|\n|domain|evil[.]test|\n## References\nhttps://reference.test",
    )
    assert len(rows) == 1
    rows, _ = parse_file(
        "talos",
        "iocs.json",
        json.dumps({"indicators": [{"type": "domain", "value": "evil.test"}]}).encode(),
    )
    assert len(rows) == 1
    for path in ("../evil.txt", "sample.py", "passwords.txt", "http://evil.txt", "sample.zip"):
        assert not supported_path("talos", path)
    for payload in (b"x" * 2_000_001, b"\x00", b"\xff"):
        with pytest.raises((ValueError, UnicodeError)):
            parse_file("talos", "iocs.txt", payload)


def test_storage_replacement_provenance_filters_retention(db):
    a, b = normalize("evil.test"), normalize("192.0.2.1")
    assert a and b
    db.save(report(), (a, b), {"cursor": "saved"})
    db.save(report("two", "eset"), (a,), {})
    assert db.feed.state("cursor") == "saved"
    result = listing(db, view="indicators")
    assert result.total == 2 and len(result.items[0].reports) >= 1
    db.save(report(), (b,), {})
    clear_cache()
    assert len(db.detail("one")[1]) == 1
    assert listing(db, query="evil.test").total == 1
    assert listing(db, vendor="talos", kind="domain").total == 0
    assert listing(db, page_size=1).total == 2
    assert listing(db, query="%'").total == 0
    db.prune(NOW + timedelta(seconds=1))
    assert db.detail("one") is None


def test_sqlite_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "rollback.db"))
    db = IocStorage(FeedStorage())
    item = normalize("evil.test")
    assert item
    with pytest.raises(sqlite3.IntegrityError):
        db.save(report(), (item, item), {"cursor": "advanced"})
    assert db.detail("one") is None and db.feed.state("cursor") is None


@pytest.mark.asyncio
async def test_incremental_collection_resume_and_skipped_code(db, monkeypatch):
    files = [{"filename": f"iocs-{i}.txt", "sha": SHA} for i in range(6)] + [
        {"filename": "payload.py"}
    ]
    payloads = [
        json.dumps([{"sha": SHA, "commit": {"committer": {"date": NOW.isoformat()}}}]).encode(),
        json.dumps({"files": files}).encode(),
    ] + [b"evil.test"] * 6
    budget = DownloadBudget()
    mocked = AsyncMock(side_effect=payloads)
    monkeypatch.setattr(budget, "fetch", mocked)
    assert await collect_source(db, SOURCES[0], budget, NOW) == 5
    assert statuses(db)[0].status == "partial"
    assert await collect_source(db, SOURCES[0], budget, NOW) == 1
    assert statuses(db)[0].status == "current" and mocked.await_count == 8


@pytest.mark.asyncio
async def test_failed_save_keeps_pending_and_no_cursor_advance(db, monkeypatch):
    state = {
        "since": (NOW - timedelta(days=30)).isoformat(),
        "until": NOW.isoformat(),
        "page": 2,
        "discovered": True,
        "commits": [{"sha": SHA, "date": NOW.isoformat()}],
        "files": [{"path": "iocs.txt", "blob": SHA, "removed": False}],
    }
    db.feed.set_state("ioc_cursor:talos", json.dumps(state))
    budget = DownloadBudget()
    monkeypatch.setattr(budget, "fetch", AsyncMock(return_value=b"evil.test"))
    monkeypatch.setattr(db, "save", lambda *_: (_ for _ in ()).throw(ValueError("secret")))
    await collect_source(db, SOURCES[0], budget, NOW)
    after = json.loads(db.feed.state("ioc_cursor:talos"))
    assert after["files"] and after["since"] == state["since"]
    assert (
        statuses(db)[0].status == "unavailable"
        and "secret" not in statuses(db)[0].model_dump_json()
    )


@pytest.mark.asyncio
async def test_rate_limit_and_payload_caps(monkeypatch):
    factory = httpx.AsyncClient
    for status, body, headers in [
        (429, b"", {"retry-after": "60"}),
        (302, b"", {}),
        (200, b"x" * 2_000_001, {}),
    ]:
        transport = httpx.MockTransport(
            lambda request, status=status, body=body, headers=headers: httpx.Response(
                status, content=body, headers=headers
            )
        )
        async with factory(transport=transport, follow_redirects=False) as client:
            with pytest.raises((RateLimited, httpx.HTTPStatusError, ValueError)):
                await DownloadBudget().fetch(
                    client, "https://api.github.com/repos/Cisco-Talos/IOCs/commits", api=True
                )


@pytest.mark.asyncio
async def test_unparseable_update_preserves_existing_indicators(db, monkeypatch):
    report_id = identity("talos:iocs.txt")
    item = normalize("evil.test")
    assert item
    db.save(report(report_id, when=NOW - timedelta(days=1)), (item,), {})
    state = {
        "since": (NOW - timedelta(days=30)).isoformat(),
        "until": NOW.isoformat(),
        "page": 2,
        "discovered": True,
        "commits": [{"sha": SHA, "date": NOW.isoformat()}],
        "files": [{"path": "iocs.txt", "blob": SHA, "removed": False}],
    }
    db.feed.set_state("ioc_cursor:talos", json.dumps(state))
    budget = DownloadBudget()
    monkeypatch.setattr(budget, "fetch", AsyncMock(return_value=b"Unknown new format"))
    assert await collect_source(db, SOURCES[0], budget, NOW) == 0
    assert db.detail(report_id)[1] == (item,)
    assert json.loads(db.feed.state("ioc_cursor:talos"))["files"]
    assert statuses(db)[0].status == "unavailable"


def test_public_api_and_validation(db):
    app = FastAPI()
    app.include_router(ioc_reports.router)
    app.dependency_overrides[ioc_reports.storage] = lambda: db
    item = normalize("evil.test")
    assert item
    db.save(report(), (item,), {})
    client = TestClient(app)
    assert client.get("/api/v1/threat-feed/ioc-reports").status_code == 200
    assert client.get("/api/v1/threat-feed/indicators").json()["total"] == 1
    assert (
        client.get("/api/v1/threat-feed/ioc-reports/one").json()["indicators"][0]["verified"]
        is False
    )
    assert (
        client.get("/api/v1/threat-feed/ioc-reports/one/indicators?page_size=1").json()["total"]
        == 1
    )
    assert client.get("/api/v1/threat-feed/ioc-reports?hours=999999").status_code == 422
    assert client.get("/api/v1/threat-feed/ioc-reports/missing").status_code == 404


def test_production_storage_fails_closed(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    with pytest.raises(ValueError):
        IocStorage(FeedStorage())


def test_storage_budget_keeps_existing_records(db, monkeypatch):
    monkeypatch.setattr("threatlens.ioc_feed.storage.MAX_REPORTS", 1)
    item = normalize("evil.test")
    assert item
    db.save(report(), (item,), {})
    with pytest.raises(StorageCapacity):
        db.save(report("two"), (item,), {"cursor": "skipped"})
    assert db.detail("one") and not db.detail("two") and db.feed.state("cursor") is None


@pytest.mark.asyncio
async def test_shared_refresh_wiring_and_cooldown(db, monkeypatch):
    service = ThreatFeedService(db.feed)
    monkeypatch.setattr(service, "_collect", AsyncMock(return_value=(0, 0)))
    monkeypatch.setattr("threatlens.threat_feed.service.sync_nvd", AsyncMock())
    collected = AsyncMock(return_value=0)
    monkeypatch.setattr("threatlens.ioc_feed.collector.collect", collected)
    assert (await service.refresh()).status == "completed"
    collected.assert_awaited_once()
    assert collected.call_args.args[0].feed is db.feed
    assert (await service.refresh()).status == "cooldown"
    assert collected.await_count == 1
