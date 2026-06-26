"""Integration tests for the AbuseIPDB provider (Phase 1.6).

Every external request is mocked with ``httpx.MockTransport`` — the live
AbuseIPDB service is never contacted. Covers IPv4/IPv6 success, non-global IP
short-circuits, failure mapping, normalization, and aggregation compatibility.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import (
    AbuseIPDBProvider,
    EvidenceType,
    HttpClient,
    RelationshipTargetType,
    RelationshipType,
    ReputationLevel,
    ResultStatus,
    aggregate,
)

Handler = Callable[[httpx.Request], httpx.Response]


def _data(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ipAddress": "118.25.6.39",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Tencent Cloud Computing",
        "domain": "tencent.com",
        "hostnames": ["host.example"],
        "isTor": False,
        "totalReports": 42,
        "numDistinctUsers": 18,
        "lastReportedAt": "2023-10-01T12:34:56+00:00",
        "reports": [{"categories": [18, 22]}, {"categories": [14]}],
    }
    base.update(overrides)
    return base


def ok_response(**overrides: object) -> dict[str, object]:
    return {"data": _data(**overrides)}


def make_provider(handler: Handler, *, api_key: str | None = "test-key") -> AbuseIPDBProvider:
    client = HttpClient(transport=httpx.MockTransport(handler), max_retries=2, backoff=0)
    return AbuseIPDBProvider(api_key=api_key, http_client=client)


def json_handler(payload: object, *, status: int = 200) -> Handler:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


def ip_entity(value: str, entity_type: EntityType = EntityType.IPV4) -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
    )


# --- successful lookups ---


async def test_ipv4_lookup_success() -> None:
    result = await make_provider(json_handler(ok_response())).search(ip_entity("118.25.6.39"))
    assert result.status is ResultStatus.OK
    assert result.provider == "abuseipdb"
    assert result.reputation is not None
    assert result.reputation.level is ReputationLevel.MALICIOUS
    assert result.reputation.score == 100

    assert any(e.type is EvidenceType.ABUSE_CONFIDENCE for e in result.evidence)
    assert any(
        e.type is EvidenceType.LAST_SEEN and e.observed_at is not None for e in result.evidence
    )
    # categories 18/22/14 -> Brute-Force / SSH / Port Scan
    cats = {e.value for e in result.evidence if e.type is EvidenceType.CATEGORY}
    assert {"Brute-Force", "SSH", "Port Scan"} <= cats
    assert {"Brute-Force", "SSH", "Port Scan"} <= set(result.tags)

    rels = {(r.relationship, r.target_type, r.target_value) for r in result.relationships}
    assert (RelationshipType.RELATED_TO, RelationshipTargetType.INDICATOR, "tencent.com") in rels
    assert (RelationshipType.RESOLVES_TO, RelationshipTargetType.INDICATOR, "host.example") in rels
    assert any("abuseipdb.com/check/118.25.6.39" in ref.url for ref in result.references)


async def test_ipv6_lookup_success() -> None:
    handler = json_handler(ok_response(ipAddress="2001:4860:4860::8888", ipVersion=6))
    result = await make_provider(handler).search(ip_entity("2001:4860:4860::8888", EntityType.IPV6))
    assert result.status is ResultStatus.OK
    assert result.entity_type is EntityType.IPV6


async def test_request_is_get_with_key_header_and_ip_param() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["key"] = request.headers.get("Key", "")
        captured["ip"] = request.url.params.get("ipAddress", "")
        return httpx.Response(200, json=ok_response())

    await make_provider(handler, api_key="secret").search(ip_entity("118.25.6.39"))
    assert captured["method"] == "GET"
    assert captured["key"] == "secret"
    assert captured["ip"] == "118.25.6.39"


async def test_whitelisted_is_benign_and_zero_score_is_unknown() -> None:
    wl = await make_provider(json_handler(ok_response(isWhitelisted=True))).search(
        ip_entity("118.25.6.39")
    )
    assert wl.reputation is not None and wl.reputation.level is ReputationLevel.BENIGN

    clean = await make_provider(
        json_handler(ok_response(abuseConfidenceScore=0, isWhitelisted=False, reports=[]))
    ).search(ip_entity("118.25.6.39"))
    assert clean.reputation is not None and clean.reputation.level is ReputationLevel.UNKNOWN


# --- non-global IPs short-circuit (no request) ---


async def test_private_ipv4_is_not_found_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=ok_response())

    result = await make_provider(handler).search(ip_entity("192.168.1.10"))
    assert result.status is ResultStatus.NOT_FOUND
    assert calls["n"] == 0


async def test_private_ipv6_is_not_found_without_request() -> None:
    result = await make_provider(json_handler(ok_response())).search(
        ip_entity("fd00::1", EntityType.IPV6)
    )
    assert result.status is ResultStatus.NOT_FOUND


async def test_reserved_ip_is_not_found_without_request() -> None:
    result = await make_provider(json_handler(ok_response())).search(ip_entity("240.0.0.1"))
    assert result.status is ResultStatus.NOT_FOUND


async def test_invalid_ip_is_error_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=ok_response())

    result = await make_provider(handler).search(ip_entity("999.999.999.999"))
    assert result.status is ResultStatus.ERROR
    assert calls["n"] == 0


# --- auth / failures ---


async def test_missing_api_key_is_unauthorized_without_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=ok_response())

    result = await make_provider(handler, api_key=None).search(ip_entity("118.25.6.39"))
    assert result.status is ResultStatus.UNAUTHORIZED
    assert calls["n"] == 0


async def test_invalid_api_key_is_unauthorized() -> None:
    result = await make_provider(json_handler({"errors": []}, status=401)).search(
        ip_entity("118.25.6.39")
    )
    assert result.status is ResultStatus.UNAUTHORIZED


async def test_rate_limit_is_mapped() -> None:
    result = await make_provider(json_handler({"errors": []}, status=429)).search(
        ip_entity("118.25.6.39")
    )
    assert result.status is ResultStatus.RATE_LIMITED
    assert result.error is not None and result.error.retryable is True


async def test_timeout_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    result = await make_provider(handler).search(ip_entity("118.25.6.39"))
    assert result.status is ResultStatus.TIMEOUT
    assert result.error is not None and result.error.retryable is True


async def test_network_failure_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = await make_provider(handler).search(ip_entity("118.25.6.39"))
    assert result.status is ResultStatus.ERROR
    assert result.error is not None and result.error.retryable is True


async def test_unsupported_entity_makes_no_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=ok_response())

    result = await make_provider(handler).search(ip_entity("evil.com", EntityType.DOMAIN))
    assert result.status is ResultStatus.UNSUPPORTED
    assert calls["n"] == 0


# --- normalization / aggregation ---


async def test_normalize_data_object() -> None:
    result = await make_provider(json_handler(ok_response())).normalize(_data())
    assert result.status is ResultStatus.OK
    assert result.entity_type is EntityType.IPV4
    assert result.entity_value == "118.25.6.39"


async def test_result_flows_through_aggregation() -> None:
    result = await make_provider(json_handler(ok_response())).search(ip_entity("118.25.6.39"))
    agg = aggregate([result], entity_type=EntityType.IPV4, entity_value="118.25.6.39")
    assert [p.provider for p in agg.providers] == ["abuseipdb"]
    assert agg.providers[0].reputation is not None
    assert all(e.sources == ["abuseipdb"] for e in agg.evidence)
