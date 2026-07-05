"""Tests for GreyNoiseProvider (Phase 5.3 — third concrete exposure provider).

Every external request is mocked with ``httpx.MockTransport`` — the live
GreyNoise service is never contacted and no test requires a real API key or
Internet access. Covers health, IPv4 lookup success, non-global IP
short-circuits, failure mapping (401/403/404/429/timeout/network/malformed
JSON), normalization (including the "quoted third-party classification"
evidence and the zero-assets shape), the in-memory cache, and disabled-provider
behavior.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.cache import InMemoryExposureCache
from threatlens.exposure.models import ExposureCapability, ExposureProviderStatus, ExposureStatus
from threatlens.exposure.providers.greynoise import GreyNoiseProvider
from threatlens.providers.http import HttpClient

Handler = Callable[[httpx.Request], httpx.Response]


def _context_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ip": "8.8.8.8",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "Mirai",
        "link": "https://viz.greynoise.io/ip/8.8.8.8",
        "last_seen": "2024-01-01",
        "actor": "unknown",
        "tags": ["Mirai", "Telnet Scanner"],
        "cve": ["CVE-2021-1234"],
        "vpn": True,
        "vpn_service": "NordVPN",
        "metadata": {
            "tor": False,
            "organization": "Google LLC",
            "asn": "AS15169",
            "country": "United States",
            "city": "Mountain View",
        },
    }
    base.update(overrides)
    return base


def make_provider(
    handler: Handler, *, api_key: str | None = "test-key", **kwargs: object
) -> GreyNoiseProvider:
    client = HttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    return GreyNoiseProvider(api_key=api_key, http_client=client, **kwargs)  # type: ignore[arg-type]


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
        possible_matches=[],
        routing={"providers": []},  # type: ignore[arg-type]
    )


# --- metadata ---


def test_metadata_declares_ipv4_only() -> None:
    provider = GreyNoiseProvider(api_key="k")
    assert provider.metadata.supported_entity_types == {EntityType.IPV4}
    assert provider.metadata.capabilities == {ExposureCapability.INTERNET_NOISE}


# --- successful lookup / normalization ---


async def test_ipv4_lookup_success_and_normalization() -> None:
    result = await make_provider(json_handler(_context_payload())).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.OK
    assert result.provider == "greynoise"
    assert result.category is ExposureCapability.INTERNET_NOISE

    # GreyNoise contributes no assets — every finding is evidence-only.
    assert result.assets == []

    evidence_by_type = {e.type: e for e in result.evidence}
    assert evidence_by_type["classification"].value == "malicious"
    assert "GreyNoise classification: malicious" in evidence_by_type["classification"].summary
    assert evidence_by_type["internet_scanner"].value == "true"
    assert evidence_by_type["name"].value == "Mirai"
    assert evidence_by_type["vpn"].value == "NordVPN"
    assert evidence_by_type["organization"].value == "Google LLC"
    assert evidence_by_type["asn"].value == "AS15169"
    assert evidence_by_type["country"].value == "United States"
    assert evidence_by_type["city"].value == "Mountain View"
    assert evidence_by_type["last_seen"].value == "2024-01-01"

    vuln_values = {e.value for e in result.evidence if e.type == "vulnerability"}
    assert vuln_values == {"CVE-2021-1234"}
    tag_values = {e.value for e in result.evidence if e.type == "tag"}
    assert tag_values == {"Mirai", "Telnet Scanner"}

    # riot=False and tor=False must not fabricate evidence.
    assert "business_service" not in evidence_by_type
    assert "tor" not in evidence_by_type

    assert any("viz.greynoise.io/ip/8.8.8.8" in ref.url for ref in result.references)


async def test_riot_only_yields_business_service_category_and_no_classification() -> None:
    payload = _context_payload(classification=None, noise=False, riot=True, name=None, actor=None)
    result = await make_provider(json_handler(payload)).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.OK
    assert result.category is ExposureCapability.INTERNET_NOISE
    evidence_types = {e.type for e in result.evidence}
    assert "business_service" in evidence_types
    assert "classification" not in evidence_types
    assert "internet_scanner" not in evidence_types


async def test_unknown_name_and_actor_are_not_reported_as_evidence() -> None:
    payload = _context_payload(name="unknown", actor="unknown")
    result = await make_provider(json_handler(payload)).lookup(ip_entity("8.8.8.8"))
    evidence_types = {e.type for e in result.evidence}
    assert "name" not in evidence_types
    assert "actor" not in evidence_types


async def test_tor_exit_node_is_reported() -> None:
    payload = _context_payload(metadata={"tor": True})
    result = await make_provider(json_handler(payload)).lookup(ip_entity("8.8.8.8"))
    evidence_by_type = {e.type: e for e in result.evidence}
    assert evidence_by_type["tor"].value == "true"


async def test_request_sends_key_header() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["key"] = request.headers.get("key", "")
        captured["path"] = request.url.path
        return httpx.Response(200, json=_context_payload())

    await make_provider(handler, api_key="secret").lookup(ip_entity("8.8.8.8"))
    assert captured["method"] == "GET"
    assert captured["key"] == "secret"
    assert captured["path"] == "/v2/noise/context/8.8.8.8"


async def test_normalize_raw_payload() -> None:
    result = await make_provider(json_handler(_context_payload())).normalize(_context_payload())
    assert result.status is ExposureStatus.OK
    assert result.entity_type is EntityType.IPV4
    assert result.entity_value == "8.8.8.8"


async def test_no_classification_noise_or_riot_has_no_category() -> None:
    payload = _context_payload(classification=None, noise=False, riot=False)
    result = await make_provider(json_handler(payload)).lookup(ip_entity("8.8.8.8"))
    assert result.category is None


# --- non-global IPs short-circuit (no request) ---


async def test_private_ipv4_is_not_found_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    result = await make_provider(handler).lookup(ip_entity("192.168.1.10"))
    assert result.status is ExposureStatus.NOT_FOUND
    assert calls["n"] == 0


async def test_invalid_ip_is_error_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    result = await make_provider(handler).lookup(ip_entity("999.999.999.999"))
    assert result.status is ExposureStatus.ERROR
    assert calls["n"] == 0


async def test_unsupported_entity_makes_no_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    result = await make_provider(handler).lookup(ip_entity("evil.example.com", EntityType.DOMAIN))
    assert result.status is ExposureStatus.UNSUPPORTED
    assert calls["n"] == 0


async def test_ipv6_is_unsupported_makes_no_request() -> None:
    """GreyNoise is IPv4-only — this is GreyNoise's own scope, not ThreatLens's choice."""
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    result = await make_provider(handler).lookup(ip_entity("2001:4860:4860::8888", EntityType.IPV6))
    assert result.status is ExposureStatus.UNSUPPORTED
    assert calls["n"] == 0


# --- auth / http failure mapping ---


async def test_missing_api_key_is_unauthorized_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    result = await make_provider(handler, api_key=None).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.UNAUTHORIZED
    assert calls["n"] == 0


async def test_401_is_unauthorized() -> None:
    result = await make_provider(json_handler({"error": "Invalid key"}, status=401)).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.UNAUTHORIZED


async def test_403_is_unauthorized() -> None:
    result = await make_provider(json_handler({"error": "Forbidden"}, status=403)).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.UNAUTHORIZED


async def test_404_is_not_found() -> None:
    result = await make_provider(json_handler({"error": "not found"}, status=404)).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.NOT_FOUND
    assert result.error is None


async def test_429_is_rate_limited() -> None:
    result = await make_provider(json_handler({"error": "Rate limit"}, status=429)).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.RATE_LIMITED
    assert result.error is not None and result.error.retryable is True


async def test_5xx_is_mapped_to_error_after_retries_exhausted() -> None:
    result = await make_provider(json_handler({"error": "boom"}, status=500)).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.ERROR
    assert result.error is not None and result.error.retryable is True


async def test_timeout_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    result = await make_provider(handler).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.TIMEOUT
    assert result.error is not None and result.error.retryable is True


async def test_network_failure_is_mapped() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    result = await make_provider(handler).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.ERROR
    assert result.error is not None and result.error.retryable is True


async def test_malformed_json_is_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json{")

    result = await make_provider(handler).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.ERROR


async def test_unexpected_payload_shape_is_error() -> None:
    result = await make_provider(json_handler(["not", "a", "mapping"])).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.ERROR


# --- health() ---


async def test_health_operational_when_reachable_and_authorized() -> None:
    provider = make_provider(json_handler({"offline": False}))
    health = await provider.health()
    assert health.status is ExposureProviderStatus.OPERATIONAL


async def test_health_degraded_when_no_api_key() -> None:
    """Unlike Censys's PAT-migration DISABLED convention, GreyNoise follows
    Shodan's original convention: missing credentials is DEGRADED, not
    DISABLED — the task did not request the DISABLED distinction here."""
    provider = make_provider(json_handler({}), api_key=None)
    health = await provider.health()
    assert health.status is ExposureProviderStatus.DEGRADED
    assert health.detail == "API key not configured"


async def test_health_degraded_on_401() -> None:
    provider = make_provider(json_handler({"error": "Invalid key"}, status=401))
    health = await provider.health()
    assert health.status is ExposureProviderStatus.DEGRADED


async def test_health_unavailable_on_timeout() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    health = await make_provider(handler).health()
    assert health.status is ExposureProviderStatus.UNAVAILABLE


async def test_health_unavailable_on_network_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    health = await make_provider(handler).health()
    assert health.status is ExposureProviderStatus.UNAVAILABLE


async def test_health_disabled_when_provider_disabled() -> None:
    provider = GreyNoiseProvider(api_key="k", enabled=False)
    health = await provider.health()
    assert health.status is ExposureProviderStatus.DISABLED


# --- disabled provider ---


def test_disabled_flag_reflected_in_metadata() -> None:
    provider = GreyNoiseProvider(api_key="k", enabled=False)
    assert provider.metadata.enabled is False
    assert provider.enabled is False


def test_enabled_flag_from_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GREYNOISE_ENABLED", "false")
    provider = GreyNoiseProvider(api_key="k")
    assert provider.metadata.enabled is False


# --- configuration() ---


async def test_configuration_reports_status_without_leaking_key() -> None:
    provider = GreyNoiseProvider(
        api_key="super-secret", base_url="https://example.test", timeout=5.0
    )
    config = await provider.configuration()
    assert config == {
        "api_key_configured": True,
        "base_url": "https://example.test",
        "timeout": 5.0,
        "enabled": True,
    }
    assert "super-secret" not in str(config)


# --- cache ---


async def test_repeat_lookup_is_served_from_cache() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    provider = make_provider(handler)
    entity = ip_entity("8.8.8.8")
    first = await provider.lookup(entity)
    second = await provider.lookup(entity)
    assert calls["n"] == 1
    assert first is second


async def test_cache_expires_after_ttl() -> None:
    clock = {"now": 0.0}
    cache = InMemoryExposureCache(clock=lambda: clock["now"])
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_context_payload())

    provider = make_provider(handler, cache=cache)
    entity = ip_entity("8.8.8.8")
    await provider.lookup(entity)
    clock["now"] += 3600.0 + 1.0
    await provider.lookup(entity)
    assert calls["n"] == 2


async def test_rate_limited_result_is_never_cached() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, json={"error": "slow down"})

    provider = make_provider(handler)
    entity = ip_entity("8.8.8.8")
    await provider.lookup(entity)
    await provider.lookup(entity)
    assert calls["n"] == 2


async def test_unauthorized_result_is_never_cached_so_a_fixed_key_retries() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": "Invalid key"})

    provider = make_provider(handler)
    entity = ip_entity("8.8.8.8")
    await provider.lookup(entity)
    await provider.lookup(entity)
    assert calls["n"] == 2


async def test_not_found_is_cached() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, json={"error": "not found"})

    provider = make_provider(handler)
    entity = ip_entity("8.8.8.8")
    await provider.lookup(entity)
    await provider.lookup(entity)
    assert calls["n"] == 1
