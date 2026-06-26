"""Integration tests for the URLhaus provider (Phase 1.5).

Every external request is mocked with ``httpx.MockTransport`` — the live URLhaus
service is never contacted. Covers URL and host (domain) lookups, failure
mapping, normalization, and aggregation compatibility.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import (
    EvidenceType,
    HttpClient,
    RelationshipTargetType,
    RelationshipType,
    ReputationLevel,
    ResultStatus,
    UrlhausProvider,
    aggregate,
)

Handler = Callable[[httpx.Request], httpx.Response]

URL_OK = {
    "query_status": "ok",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
    "url": "http://evil.example/payload.exe",
    "url_status": "online",
    "host": "evil.example",
    "date_added": "2024-01-02 03:04:05 UTC",
    "threat": "malware_download",
    "reporter": "abuse_ch",
    "tags": ["exe", "Emotet"],
    "payloads": [
        {
            "response_sha256": "a" * 64,
            "file_type": "exe",
            "signature": "Emotet",
            "filename": "payload.exe",
        }
    ],
}

HOST_OK = {
    "query_status": "ok",
    "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.example/",
    "host": "evil.example",
    "firstseen": "2023-05-01 00:00:00 UTC",
    "url_count": "3",
    "urls": [
        {
            "url": "http://evil.example/a",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe"],
        },
        {
            "url": "http://evil.example/b",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": ["Emotet"],
        },
    ],
}


def make_provider(handler: Handler, *, auth_key: str | None = "test-key") -> UrlhausProvider:
    client = HttpClient(transport=httpx.MockTransport(handler), max_retries=2, backoff=0)
    return UrlhausProvider(auth_key=auth_key, http_client=client)


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


def url_entity(value: str = "http://evil.example/payload.exe") -> Entity:
    return entity_of(EntityType.URL, value)


def domain_entity(value: str = "evil.example") -> Entity:
    return entity_of(EntityType.DOMAIN, value)


# --- successful lookups ---


async def test_url_lookup_success() -> None:
    result = await make_provider(json_handler(URL_OK)).search(url_entity())
    assert result.status is ResultStatus.OK
    assert result.provider == "urlhaus"
    assert result.reputation is not None
    assert result.reputation.level is ReputationLevel.MALICIOUS
    assert "Emotet" in result.tags

    families = [e.value for e in result.evidence if e.type is EvidenceType.MALWARE_FAMILY]
    assert families == ["Emotet"]
    assert any(
        e.type is EvidenceType.CATEGORY and e.value == "malware_download" for e in result.evidence
    )

    rels = {(r.relationship, r.target_type, r.target_value) for r in result.relationships}
    assert (RelationshipType.RELATED_TO, RelationshipTargetType.INDICATOR, "evil.example") in rels
    assert (RelationshipType.DROPS, RelationshipTargetType.INDICATOR, "a" * 64) in rels
    assert (RelationshipType.INDICATES, RelationshipTargetType.MALWARE_FAMILY, "Emotet") in rels
    assert any("urlhaus.abuse.ch/url/" in ref.url for ref in result.references)


async def test_host_lookup_success() -> None:
    result = await make_provider(json_handler(HOST_OK)).search(domain_entity())
    assert result.status is ResultStatus.OK
    assert result.reputation is not None and result.reputation.level is ReputationLevel.MALICIOUS
    assert any("Malicious URLs observed" in e.summary for e in result.evidence)
    assert any(
        e.type is EvidenceType.CATEGORY and e.value == "malware_download" for e in result.evidence
    )

    targets = {r.target_value for r in result.relationships}
    assert {"http://evil.example/a", "http://evil.example/b"} <= targets
    assert any("urlhaus.abuse.ch/host/" in ref.url for ref in result.references)


async def test_url_and_host_use_correct_endpoint_and_field() -> None:
    captured: dict[str, str] = {}

    def handler(payload: object) -> Handler:
        def inner(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["body"] = request.content.decode()
            captured["auth"] = request.headers.get("Auth-Key", "")
            return httpx.Response(200, json=payload)

        return inner

    await make_provider(handler(URL_OK), auth_key="k").search(url_entity("http://x.test/p"))
    assert captured["path"].endswith("/url/")
    assert "url=" in captured["body"]
    assert captured["auth"] == "k"

    await make_provider(handler(HOST_OK)).search(domain_entity("x.test"))
    assert captured["path"].endswith("/host/")
    assert "host=" in captured["body"]


# --- not found / invalid ---


async def test_unknown_url_is_not_found() -> None:
    result = await make_provider(json_handler({"query_status": "no_results"})).search(url_entity())
    assert result.status is ResultStatus.NOT_FOUND
    assert not result.has_findings


async def test_unknown_domain_is_not_found() -> None:
    result = await make_provider(json_handler({"query_status": "no_results"})).search(
        domain_entity()
    )
    assert result.status is ResultStatus.NOT_FOUND


async def test_invalid_url_is_error() -> None:
    result = await make_provider(json_handler({"query_status": "invalid_url"})).search(url_entity())
    assert result.status is ResultStatus.ERROR
    assert result.error is not None


async def test_invalid_domain_is_error() -> None:
    result = await make_provider(json_handler({"query_status": "invalid_host"})).search(
        domain_entity()
    )
    assert result.status is ResultStatus.ERROR


# --- failures / unsupported ---


async def test_timeout_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    result = await make_provider(handler).search(url_entity())
    assert result.status is ResultStatus.TIMEOUT
    assert result.error is not None and result.error.retryable is True


async def test_network_failure_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = await make_provider(handler).search(domain_entity())
    assert result.status is ResultStatus.ERROR
    assert result.error is not None and result.error.retryable is True


async def test_unauthorized_is_mapped() -> None:
    result = await make_provider(json_handler({}, status=401)).search(url_entity())
    assert result.status is ResultStatus.UNAUTHORIZED


async def test_unsupported_entity_makes_no_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=URL_OK)

    result = await make_provider(handler).search(entity_of(EntityType.SHA256, "a" * 64))
    assert result.status is ResultStatus.UNSUPPORTED
    assert calls["n"] == 0


# --- normalization ---


async def test_normalize_url_payload() -> None:
    result = await make_provider(json_handler(URL_OK)).normalize(URL_OK)
    assert result.status is ResultStatus.OK
    assert result.entity_type is EntityType.URL
    assert result.entity_value == "http://evil.example/payload.exe"


async def test_normalize_host_payload() -> None:
    result = await make_provider(json_handler(HOST_OK)).normalize(HOST_OK)
    assert result.status is ResultStatus.OK
    assert result.entity_type is EntityType.DOMAIN
    assert result.entity_value == "evil.example"


# --- aggregation compatibility ---


async def test_result_flows_through_aggregation() -> None:
    result = await make_provider(json_handler(URL_OK)).search(url_entity())
    agg = aggregate(
        [result], entity_type=EntityType.URL, entity_value="http://evil.example/payload.exe"
    )
    assert [p.provider for p in agg.providers] == ["urlhaus"]
    assert agg.providers[0].status is ResultStatus.OK
    assert all(e.sources == ["urlhaus"] for e in agg.evidence)
    assert any(
        r.relationship.target_value == "Emotet" and r.sources == ["urlhaus"]
        for r in agg.relationships
    )
