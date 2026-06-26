"""Integration tests for the AlienVault OTX provider (Phase 1.7).

Every external request is mocked with ``httpx.MockTransport`` — the live OTX API
is never contacted. Covers multi-type lookups, anonymous mode, failure mapping,
relationship extraction, normalization, and aggregation compatibility.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import unquote

import httpx
import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import (
    EvidenceType,
    HttpClient,
    OTXProvider,
    RelationshipTargetType,
    RelationshipType,
    ReputationLevel,
    ResultStatus,
    aggregate,
)

Handler = Callable[[httpx.Request], httpx.Response]

GENERAL_OK = {
    "indicator": "1.2.3.4",
    "type": "IPv4",
    "pulse_info": {
        "count": 2,
        "pulses": [
            {
                "id": "p1",
                "name": "Emotet Campaign",
                "created": "2023-01-01T00:00:00",
                "modified": "2023-02-01T00:00:00",
                "tags": ["emotet", "banking"],
                "references": ["http://ref1"],
                "malware_families": [{"display_name": "Emotet"}],
                "attack_ids": [{"id": "T1059"}],
                "adversary": "TA542",
            },
            {
                "id": "p2",
                "name": "Generic Banking",
                "created": "2022-12-01T00:00:00",
                "modified": "2023-03-01T00:00:00",
                "tags": ["banking"],
                "references": ["http://ref2"],
                "malware_families": ["TrickBot"],
                "attack_ids": ["T1071"],
                "adversary": "",
            },
        ],
    },
}

EMPTY = {"indicator": "1.2.3.4", "type": "IPv4", "pulse_info": {"count": 0, "pulses": []}}


def make_provider(handler: Handler, *, api_key: str | None = "test-key") -> OTXProvider:
    client = HttpClient(transport=httpx.MockTransport(handler), max_retries=2, backoff=0)
    return OTXProvider(api_key=api_key, http_client=client)


def json_handler(payload: object, *, status: int = 200) -> Handler:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return handler


def entity_of(entity_type: EntityType, value: str) -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
    )


# --- successful lookups + relationship extraction ---


async def test_ip_lookup_success_extracts_relationships() -> None:
    result = await make_provider(json_handler(GENERAL_OK)).search(
        entity_of(EntityType.IPV4, "1.2.3.4")
    )
    assert result.status is ResultStatus.OK
    assert result.provider == "otx"
    assert result.reputation is not None
    assert result.reputation.level is ReputationLevel.SUSPICIOUS

    families = {e.value for e in result.evidence if e.type is EvidenceType.MALWARE_FAMILY}
    assert {"Emotet", "TrickBot"} == families
    pulses = {e.value for e in result.evidence if e.type is EvidenceType.PULSE_MATCH}
    assert {"Emotet Campaign", "Generic Banking"} == pulses
    assert {"emotet", "banking"} <= set(result.tags)

    rels = {(r.relationship, r.target_type, r.target_value) for r in result.relationships}
    assert (RelationshipType.INDICATES, RelationshipTargetType.MALWARE_FAMILY, "Emotet") in rels
    assert (RelationshipType.INDICATES, RelationshipTargetType.MALWARE_FAMILY, "TrickBot") in rels
    assert (RelationshipType.ATTRIBUTED_TO, RelationshipTargetType.THREAT_ACTOR, "TA542") in rels
    assert (RelationshipType.USES, RelationshipTargetType.ATTACK_PATTERN, "T1059") in rels
    assert (RelationshipType.USES, RelationshipTargetType.ATTACK_PATTERN, "T1071") in rels
    # Empty adversary must not produce a threat-actor relationship.
    actors = [
        r for r in result.relationships if r.target_type is RelationshipTargetType.THREAT_ACTOR
    ]
    assert [r.target_value for r in actors] == ["TA542"]

    assert {ref.url for ref in result.references} == {"http://ref1", "http://ref2"}
    first = next(e for e in result.evidence if e.type is EvidenceType.FIRST_SEEN)
    assert first.value == "2022-12-01T00:00:00" and first.observed_at is not None


async def test_endpoint_and_auth_header_per_type() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["key"] = request.headers.get("X-OTX-API-KEY", "")
        return httpx.Response(200, json=GENERAL_OK)

    await make_provider(handler, api_key="k").search(entity_of(EntityType.SHA256, "a" * 64))
    assert captured["path"].endswith(f"/indicators/file/{'a' * 64}/general")
    assert captured["key"] == "k"

    await make_provider(handler).search(entity_of(EntityType.DOMAIN, "evil.com"))
    assert captured["path"].endswith("/indicators/domain/evil.com/general")


async def test_url_value_is_encoded_once_in_path() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        return httpx.Response(200, json=GENERAL_OK)

    await make_provider(handler).search(entity_of(EntityType.URL, "http://evil.example/p"))
    # Single-encoded: un-quoting once recovers the original URL.
    assert unquote(captured["path"]).endswith("/indicators/url/http://evil.example/p/general")


# --- anonymous mode / auth ---


async def test_anonymous_mode_omits_key_header_and_still_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    seen: dict[str, bool] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["has_key"] = "X-OTX-API-KEY" in request.headers
        return httpx.Response(200, json=GENERAL_OK)

    result = await make_provider(handler, api_key=None).search(
        entity_of(EntityType.IPV4, "1.2.3.4")
    )
    assert seen["has_key"] is False
    assert result.status is ResultStatus.OK


async def test_unauthorized_is_mapped() -> None:
    result = await make_provider(json_handler({}, status=403)).search(
        entity_of(EntityType.IPV4, "1.2.3.4")
    )
    assert result.status is ResultStatus.UNAUTHORIZED


# --- not found / failures ---


async def test_no_pulses_is_not_found() -> None:
    result = await make_provider(json_handler(EMPTY)).search(entity_of(EntityType.IPV4, "1.2.3.4"))
    assert result.status is ResultStatus.NOT_FOUND
    assert not result.has_findings


async def test_http_404_is_not_found() -> None:
    result = await make_provider(json_handler({}, status=404)).search(
        entity_of(EntityType.DOMAIN, "evil.com")
    )
    assert result.status is ResultStatus.NOT_FOUND


async def test_rate_limit_is_mapped() -> None:
    result = await make_provider(json_handler({}, status=429)).search(
        entity_of(EntityType.IPV4, "1.2.3.4")
    )
    assert result.status is ResultStatus.RATE_LIMITED
    assert result.error is not None and result.error.retryable is True


async def test_timeout_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    result = await make_provider(handler).search(entity_of(EntityType.IPV4, "1.2.3.4"))
    assert result.status is ResultStatus.TIMEOUT
    assert result.error is not None and result.error.retryable is True


async def test_network_failure_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = await make_provider(handler).search(entity_of(EntityType.SHA1, "b" * 40))
    assert result.status is ResultStatus.ERROR
    assert result.error is not None and result.error.retryable is True


async def test_unsupported_entity_makes_no_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=GENERAL_OK)

    result = await make_provider(handler).search(entity_of(EntityType.CVE, "CVE-2024-3094"))
    assert result.status is ResultStatus.UNSUPPORTED
    assert calls["n"] == 0


# --- normalization / aggregation ---


async def test_normalize_payload() -> None:
    result = await make_provider(json_handler(GENERAL_OK)).normalize(GENERAL_OK)
    assert result.status is ResultStatus.OK
    assert result.entity_type is EntityType.IPV4
    assert result.entity_value == "1.2.3.4"


async def test_result_flows_through_aggregation() -> None:
    result = await make_provider(json_handler(GENERAL_OK)).search(
        entity_of(EntityType.IPV4, "1.2.3.4")
    )
    agg = aggregate([result], entity_type=EntityType.IPV4, entity_value="1.2.3.4")
    assert [p.provider for p in agg.providers] == ["otx"]
    assert all(e.sources == ["otx"] for e in agg.evidence)
    assert any(
        r.relationship.target_value == "Emotet" and r.sources == ["otx"] for r in agg.relationships
    )
