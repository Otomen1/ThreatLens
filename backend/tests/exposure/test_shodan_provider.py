"""Tests for ShodanProvider (Phase 5.1 — first concrete exposure provider).

Every external request is mocked with ``httpx.MockTransport`` — the live
Shodan service is never contacted and no test requires a real API key or
Internet access. Covers health, IPv4/IPv6 lookup success, non-global IP
short-circuits, failure mapping (401/403/404/429/timeout/network/malformed
JSON), normalization, the in-memory cache, and disabled-provider behavior.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.cache import InMemoryExposureCache
from threatlens.exposure.models import ExposureCapability, ExposureProviderStatus, ExposureStatus
from threatlens.exposure.providers.shodan import ShodanProvider
from threatlens.providers.http import HttpClient

Handler = Callable[[httpx.Request], httpx.Response]


def _host_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ip_str": "8.8.8.8",
        "ports": [53, 443],
        "hostnames": ["dns.google"],
        "domains": ["dns.google"],
        "org": "Google LLC",
        "isp": "Google LLC",
        "asn": "AS15169",
        "country_name": "United States",
        "city": None,
        "os": None,
        "tags": ["cloud"],
        "vulns": ["CVE-2021-1234"],
        "last_update": "2024-01-01T00:00:00.000000",
        "data": [
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.18.0",
                "timestamp": "2024-01-01T00:00:00",
                "_shodan": {"module": "https"},
                "ssl": {
                    "cert": {
                        "subject": {"CN": "dns.google"},
                        "issuer": {"CN": "GTS CA 1C3"},
                        "expires": "20250101000000Z",
                        "fingerprint": {"sha256": "abcd1234"},
                    }
                },
                "http": {"title": "Google Public DNS"},
            },
            {"port": 53, "transport": "udp", "timestamp": "2024-01-01T00:00:00"},
        ],
    }
    base.update(overrides)
    return base


def make_provider(
    handler: Handler, *, api_key: str | None = "test-key", **kwargs: object
) -> ShodanProvider:
    client = HttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    return ShodanProvider(api_key=api_key, http_client=client, **kwargs)  # type: ignore[arg-type]


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


def test_metadata_declares_ipv4_ipv6_only() -> None:
    provider = ShodanProvider(api_key="k")
    assert provider.metadata.supported_entity_types == {EntityType.IPV4, EntityType.IPV6}
    assert provider.metadata.capabilities == {
        ExposureCapability.OPEN_PORTS,
        ExposureCapability.SERVICES,
        ExposureCapability.CERTIFICATES,
        ExposureCapability.HOSTING,
        ExposureCapability.ASN,
    }


# --- successful lookup / normalization ---


async def test_ipv4_lookup_success_and_normalization() -> None:
    result = await make_provider(json_handler(_host_payload())).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.OK
    assert result.provider == "shodan"
    assert result.category is ExposureCapability.OPEN_PORTS

    port_assets = {a.value: a for a in result.assets if a.asset_type == "open_port"}
    assert port_assets["443"].attributes["product"] == "nginx"
    assert port_assets["443"].attributes["service"] == "https"
    assert port_assets["53"].attributes["transport"] == "udp"

    cert_assets = [a for a in result.assets if a.asset_type == "certificate"]
    assert cert_assets[0].value == "dns.google"
    assert cert_assets[0].attributes["issuer"] == "GTS CA 1C3"

    assert any(a.asset_type == "hostname" and a.value == "dns.google" for a in result.assets)
    assert any(a.asset_type == "domain" and a.value == "dns.google" for a in result.assets)

    evidence_types = {e.type for e in result.evidence}
    assert {
        "organization",
        "isp",
        "asn",
        "country",
        "last_seen",
        "vulnerability",
        "tag",
        "http_title",
    } <= (evidence_types)
    assert any(e.value == "CVE-2021-1234" for e in result.evidence if e.type == "vulnerability")
    assert any("shodan.io/host/8.8.8.8" in ref.url for ref in result.references)


async def test_ipv6_lookup_preserves_entity_type() -> None:
    payload = _host_payload(ip_str="2001:4860:4860::8888")
    result = await make_provider(json_handler(payload)).lookup(
        ip_entity("2001:4860:4860::8888", EntityType.IPV6)
    )
    assert result.status is ExposureStatus.OK
    assert result.entity_type is EntityType.IPV6


async def test_request_is_get_with_key_param() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["key"] = request.url.params.get("key", "")
        captured["path"] = request.url.path
        return httpx.Response(200, json=_host_payload())

    await make_provider(handler, api_key="secret").lookup(ip_entity("8.8.8.8"))
    assert captured["method"] == "GET"
    assert captured["key"] == "secret"
    assert captured["path"] == "/shodan/host/8.8.8.8"


async def test_normalize_raw_payload() -> None:
    result = await make_provider(json_handler(_host_payload())).normalize(_host_payload())
    assert result.status is ExposureStatus.OK
    assert result.entity_type is EntityType.IPV4
    assert result.entity_value == "8.8.8.8"


async def test_host_with_no_ports_or_hosting_has_no_category() -> None:
    payload = _host_payload(
        ports=[], org=None, isp=None, asn=None, data=[], hostnames=[], domains=[]
    )
    result = await make_provider(json_handler(payload)).lookup(ip_entity("8.8.8.8"))
    assert result.category is None


# --- non-global IPs short-circuit (no request) ---


async def test_private_ipv4_is_not_found_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_host_payload())

    result = await make_provider(handler).lookup(ip_entity("192.168.1.10"))
    assert result.status is ExposureStatus.NOT_FOUND
    assert calls["n"] == 0


async def test_invalid_ip_is_error_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_host_payload())

    result = await make_provider(handler).lookup(ip_entity("999.999.999.999"))
    assert result.status is ExposureStatus.ERROR
    assert calls["n"] == 0


async def test_unsupported_entity_makes_no_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_host_payload())

    result = await make_provider(handler).lookup(ip_entity("evil.example.com", EntityType.DOMAIN))
    assert result.status is ExposureStatus.UNSUPPORTED
    assert calls["n"] == 0


# --- auth / http failure mapping ---


async def test_missing_api_key_is_unauthorized_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_host_payload())

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
    result = await make_provider(
        json_handler({"error": "No information available"}, status=404)
    ).lookup(ip_entity("8.8.8.8"))
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
    provider = make_provider(json_handler({"query_credits": 100, "plan": "dev"}))
    health = await provider.health()
    assert health.status is ExposureProviderStatus.OPERATIONAL


async def test_health_degraded_when_no_api_key() -> None:
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
    provider = ShodanProvider(api_key="k", enabled=False)
    health = await provider.health()
    assert health.status is ExposureProviderStatus.DISABLED


# --- disabled provider ---


def test_disabled_flag_reflected_in_metadata() -> None:
    provider = ShodanProvider(api_key="k", enabled=False)
    assert provider.metadata.enabled is False
    assert provider.enabled is False


def test_enabled_flag_from_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SHODAN_ENABLED", "false")
    provider = ShodanProvider(api_key="k")
    assert provider.metadata.enabled is False


# --- configuration() ---


async def test_configuration_reports_status_without_leaking_key() -> None:
    provider = ShodanProvider(api_key="super-secret", base_url="https://example.test", timeout=5.0)
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
        return httpx.Response(200, json=_host_payload())

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
        return httpx.Response(200, json=_host_payload())

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
