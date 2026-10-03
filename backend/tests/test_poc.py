import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from threatlens.api.routes import poc
from threatlens.poc.adapters import LIMITS, download_index, parse_index, safe_path
from threatlens.poc.models import LookupRequest
from threatlens.poc.service import CachedIndex, PocService
from threatlens.threat_feed.storage import FeedStorage

CVE = "CVE-2021-44228"


def module(**overrides):
    return {
        "name": "Example module",
        "fullname": "exploit/multi/example",
        "type": "exploit",
        "references": [CVE],
        "path": "modules/exploits/multi/example.rb",
        "platform": ["linux"],
        "description": "<b>Example</b>",
        "check": True,
        **overrides,
    }


def template(**overrides):
    return {
        "ID": CVE,
        "Info": {"Name": "Example detection", "Description": "Example", "Severity": "high"},
        "file_path": "http/cves/2021/CVE-2021-44228.yaml",
        **overrides,
    }


def index():
    return parse_index("metasploit", json.dumps({"one": module()}).encode())


@pytest.fixture(params=["memory", "sqlite"])
def storage(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "poc.db"))
    return FeedStorage()


def test_normalization_and_rejection():
    assert LookupRequest(cve=" cve-2021-44228 ").cve == CVE
    for value in (
        "CVE-2021-123",
        "CVE-2021-44228 extra",
        "CVE-２０２１-４４２２８",
        "https://evil.test",
    ):
        with pytest.raises(ValidationError):
            LookupRequest(cve=value)


def test_exact_references_deduplication_and_missing_values():
    data = {
        "one": module(),
        "two": module(references=["cve-2022-12345"]),
        "three": module(references=[], description=CVE),
        "bad": module(path="modules/../evil.rb"),
    }
    result = parse_index("metasploit", json.dumps(data).encode())
    assert len(result.records) == 1 and result.skipped == 1
    assert result.records[0].cves == (CVE, "CVE-2022-12345")
    partial = parse_index("nuclei", (json.dumps(template()) + "\nnot json").encode())
    assert len(partial.records) == 1 and partial.skipped == 1
    assert "<b>" not in result.records[0].description
    assert result.records[0].check_supported is True
    assert not result.records[0].locally_tested
    assert result.records[0].disclosure_date is None
    derived = parse_index(
        "metasploit", json.dumps({"one": module(path="/installed/example.rb")}).encode()
    )
    assert derived.records[0].path == "modules/exploits/multi/example.rb"


def test_nuclei_format_multiple_cves_and_unsafe_paths():
    row = template(Info={"Name": "Detection", "Classification": {"CVEID": ["CVE-2022-12345"]}})
    result = parse_index("nuclei", (json.dumps(row) + "\n" + json.dumps(template())).encode())
    assert len(result.records) == 1
    assert result.records[0].kind == "detection" and result.records[0].severity == "high"
    assert parse_index("nuclei", json.dumps(row).encode()).records[0].severity is None
    assert result.records[0].cves == (CVE, "CVE-2022-12345")
    for path in ("../evil.yaml", "http/a%2fb.yaml", "https://evil.test/a.yaml", "http//x.yaml"):
        with pytest.raises(ValueError):
            safe_path(path, source="nuclei")
    for payload in (b"{}", b"not json", b"[]", b"x" * (LIMITS["nuclei"] + 1)):
        with pytest.raises(ValueError):
            parse_index("nuclei", payload)


def test_lease_owner_cooldown_and_independent_sources(storage):
    now = datetime.now(UTC)
    assert storage.reserve_poc_source("metasploit", "one", now)[0]
    assert storage.reserve_poc_source("metasploit", "two", now)[1]
    storage.reserve_poc_source("metasploit", "two", now, release=True)
    assert storage.reserve_poc_source("metasploit", "three", now)[1]
    storage.reserve_poc_source("metasploit", "one", now, release=True)
    acquired, busy, next_at = storage.reserve_poc_source("metasploit", "four", now)
    assert not acquired and not busy and next_at == now + timedelta(seconds=60)
    assert storage.reserve_poc_source("nuclei", "five", now)[0]
    assert storage.reserve_poc_source("metasploit", "six", now + timedelta(seconds=61))[0]


def test_sqlite_cross_instance_reservations(monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "shared.db"))
    a, b = FeedStorage(), FeedStorage()
    now = datetime.now(UTC)
    assert a.reserve_poc_source("nuclei", "a", now)[0]
    assert not b.reserve_poc_source("nuclei", "b", now)[0]
    a.reserve_poc_source("nuclei", "a", now, release=True)
    assert not b.reserve_poc_source("nuclei", "b", now)[0]


@pytest.mark.asyncio
async def test_coalescing_cache_forced_refresh_and_no_matches(storage, monkeypatch):
    async def fetch(_source):
        await asyncio.sleep(0.02)
        return index()

    download = AsyncMock(side_effect=fetch)
    monkeypatch.setattr("threatlens.poc.service.download_index", download)
    service = PocService(storage)
    a, b = await asyncio.gather(
        service.lookup("metasploit", CVE), service.lookup("metasploit", CVE)
    )
    assert a.status == b.status == "completed" and download.await_count == 1
    assert (await service.lookup("metasploit", "CVE-2022-99999")).status == "no_matches"
    forced = await service.lookup("metasploit", CVE, refresh=True)
    assert forced.status == "rate_limited" and forced.stale and forced.matches
    assert forced.next_eligible_at is not None


@pytest.mark.asyncio
async def test_failures_stale_expiry_and_independent_sources(storage, monkeypatch):
    request = httpx.Request("GET", "https://example.test")
    response = httpx.Response(429, request=request)
    errors = [
        TimeoutError("secret"),
        ValueError("secret"),
        httpx.HTTPStatusError("secret", request=request, response=response),
    ]
    for error, status in zip(errors, ("timed_out", "unavailable", "rate_limited"), strict=True):
        service = PocService(storage)
        service.cache["metasploit"] = CachedIndex(index(), datetime.now(UTC) - timedelta(hours=2))
        monkeypatch.setattr("threatlens.poc.service.download_index", AsyncMock(side_effect=error))
        result = await service.lookup("metasploit", CVE, refresh=True)
        # Reset operational attempts so each isolated failure reaches the adapter.
        storage.set_state("poc_source:metasploit", "{}")
        assert result.status == status and result.stale and result.matches
        assert "secret" not in result.model_dump_json()
    service.cache["metasploit"] = CachedIndex(index(), datetime.now(UTC) - timedelta(hours=25))
    assert service.result("metasploit", CVE, failure="unavailable").matches == ()
    monkeypatch.setattr("threatlens.poc.service.download_index", AsyncMock(return_value=index()))
    assert (await service.lookup("nuclei", CVE)).status == "completed"


@pytest.mark.asyncio
async def test_overall_deadline_releases_lease(storage, monkeypatch):
    timeout = asyncio.timeout
    monkeypatch.setattr("threatlens.poc.service.asyncio.timeout", lambda _: timeout(0.01))

    async def slow_download(_source):
        await asyncio.sleep(1)
        return index()

    monkeypatch.setattr("threatlens.poc.service.download_index", slow_download)
    result = await PocService(storage).lookup("metasploit", CVE)
    assert result.status == "timed_out" and result.retryable
    acquired, busy, _ = storage.reserve_poc_source("metasploit", "next", datetime.now(UTC))
    assert not acquired and not busy


def test_response_cap(storage):
    from threatlens.poc.adapters import MetadataIndex

    records = tuple(
        index().records[0].model_copy(update={"id": str(number)}) for number in range(101)
    )
    service = PocService(storage)
    service.cache["metasploit"] = CachedIndex(MetadataIndex(records, 0), datetime.now(UTC))
    result = service.result("metasploit", CVE)
    assert len(result.matches) == 100 and result.total_matches == 101 and result.truncated


@pytest.mark.asyncio
async def test_one_hour_cache_expiry(storage, monkeypatch):
    service = PocService(storage)
    service.cache["metasploit"] = CachedIndex(index(), datetime.now(UTC) - timedelta(hours=1))
    download = AsyncMock(return_value=index())
    monkeypatch.setattr("threatlens.poc.service.download_index", download)
    result = await service.lookup("metasploit", CVE)
    assert result.status == "completed" and not result.cached
    download.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,body,headers",
    [
        (302, b"", {"Location": "https://evil.test"}),
        (200, b"bad", {}),
        (200, b"123456", {}),
    ],
)
async def test_download_rejects_redirects_oversize_and_malformed(
    monkeypatch, status, body, headers
):
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status, content=body, headers=headers)
    )
    factory = httpx.AsyncClient
    monkeypatch.setattr(
        "threatlens.poc.adapters.httpx.AsyncClient",
        lambda **kwargs: factory(transport=transport, **kwargs),
    )
    monkeypatch.setitem(LIMITS, "nuclei", 5)
    with pytest.raises((ValueError, httpx.HTTPStatusError)):
        await download_index("nuclei")


def test_private_api_fail_closed_and_valid_contract(storage, monkeypatch):
    app = FastAPI()
    app.include_router(poc.router)
    service = PocService(storage)
    service.cache["metasploit"] = CachedIndex(index(), datetime.now(UTC))
    app.dependency_overrides[poc.get_poc_service] = lambda: service
    client = TestClient(app)
    monkeypatch.setattr(poc, "supabase_auth_config", lambda: None)
    assert client.post("/api/v1/poc/lookup/metasploit", json={"cve": CVE}).status_code == 503
    monkeypatch.setattr(poc, "supabase_auth_config", lambda: ("https://auth.test", "key"))
    monkeypatch.setattr(poc, "verify_supabase_token", AsyncMock(return_value=True))
    assert client.post("/api/v1/poc/lookup/metasploit", json={"cve": CVE}).status_code == 401
    headers = {"Authorization": "Bearer mock-token"}
    result = client.post("/api/v1/poc/lookup/metasploit", json={"cve": CVE}, headers=headers)
    assert result.status_code == 200 and result.json()["cached"]
    assert result.headers["cache-control"] == "private, no-store"
    assert (
        client.post("/api/v1/poc/lookup/unknown", json={"cve": CVE}, headers=headers).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/poc/lookup/metasploit", json={"cve": "bad"}, headers=headers
        ).status_code
        == 422
    )
    monkeypatch.setattr(poc, "verify_supabase_token", AsyncMock(return_value=False))
    assert (
        client.post("/api/v1/poc/lookup/metasploit", json={"cve": CVE}, headers=headers).status_code
        == 401
    )
