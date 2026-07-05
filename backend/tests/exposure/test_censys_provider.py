"""Tests for CensysProvider (Phase 5.2 — second concrete exposure provider).

Every external request is mocked with ``httpx.MockTransport`` — the live
Censys service is never contacted and no test requires a real account or
Internet access. Covers health, IPv4/IPv6 lookup success, non-global IP
short-circuits, failure mapping (401/403/404/429/timeout/network/malformed
JSON), normalization, the in-memory cache, and disabled-provider behavior —
the same coverage shape as ``test_shodan_provider.py``, proving the
framework's per-provider testing pattern also generalizes.
"""

from __future__ import annotations

import base64
from collections.abc import Callable

import httpx

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.cache import InMemoryExposureCache
from threatlens.exposure.models import ExposureCapability, ExposureProviderStatus, ExposureStatus
from threatlens.exposure.providers.censys import CensysProvider
from threatlens.providers.http import HttpClient

Handler = Callable[[httpx.Request], httpx.Response]


def _host_result(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ip": "8.8.8.8",
        "location": {"country": "United States", "city": "Mountain View"},
        "autonomous_system": {"asn": 15169, "name": "GOOGLE"},
        "dns": {"reverse_dns": {"names": ["dns.google"]}},
        "last_updated_at": "2024-01-01T00:00:00Z",
        "services": [
            {
                "port": 443,
                "transport_protocol": "TCP",
                "service_name": "HTTP",
                "software": [{"product": "nginx", "version": "1.18.0"}],
                "tls": {
                    "certificates": {
                        "leaf_data": {
                            "subject_dn": "CN=dns.google",
                            "issuer_dn": "CN=GTS CA 1C3",
                            "fingerprint": "abcd1234",
                        }
                    }
                },
                "observed_at": "2024-01-01T00:00:00Z",
            },
            {
                "port": 53,
                "transport_protocol": "UDP",
                "service_name": "DNS",
                "observed_at": "2024-01-01T00:00:00Z",
            },
        ],
    }
    base.update(overrides)
    return base


def _envelope(result: dict[str, object]) -> dict[str, object]:
    return {"code": 200, "status": "OK", "result": result}


def make_provider(
    handler: Handler,
    *,
    api_id: str | None = "id",
    api_secret: str | None = "secret",
    **kwargs: object,
) -> CensysProvider:
    client = HttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    return CensysProvider(api_id=api_id, api_secret=api_secret, http_client=client, **kwargs)  # type: ignore[arg-type]


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
    provider = CensysProvider(api_id="id", api_secret="secret")
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
    result = await make_provider(json_handler(_envelope(_host_result()))).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.OK
    assert result.provider == "censys"
    assert result.category is ExposureCapability.OPEN_PORTS

    port_assets = {a.value: a for a in result.assets if a.asset_type == "open_port"}
    assert port_assets["443"].attributes["product"] == "nginx"
    assert port_assets["443"].attributes["service"] == "HTTP"
    assert port_assets["53"].attributes["transport"] == "udp"

    cert_assets = [a for a in result.assets if a.asset_type == "certificate"]
    assert cert_assets[0].value == "CN=dns.google"
    assert cert_assets[0].attributes["issuer"] == "CN=GTS CA 1C3"

    assert any(a.asset_type == "hostname" and a.value == "dns.google" for a in result.assets)

    evidence_types = {e.type for e in result.evidence}
    assert {"asn", "organization", "country", "city", "last_seen"} <= evidence_types
    assert any("search.censys.io/hosts/8.8.8.8" in ref.url for ref in result.references)


async def test_ipv6_lookup_preserves_entity_type() -> None:
    result = _host_result(ip="2001:4860:4860::8888")
    finding = await make_provider(json_handler(_envelope(result))).lookup(
        ip_entity("2001:4860:4860::8888", EntityType.IPV6)
    )
    assert finding.status is ExposureStatus.OK
    assert finding.entity_type is EntityType.IPV6


async def test_request_uses_basic_auth() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["authorization"] = request.headers.get("Authorization", "")
        captured["path"] = request.url.path
        return httpx.Response(200, json=_envelope(_host_result()))

    await make_provider(handler, api_id="myid", api_secret="mysecret").lookup(ip_entity("8.8.8.8"))
    assert captured["method"] == "GET"
    expected = "Basic " + base64.b64encode(b"myid:mysecret").decode()
    assert captured["authorization"] == expected
    assert captured["path"] == "/api/v2/hosts/8.8.8.8"


async def test_normalize_accepts_full_envelope() -> None:
    result = await make_provider(json_handler(_envelope(_host_result()))).normalize(
        _envelope(_host_result())
    )
    assert result.status is ExposureStatus.OK
    assert result.entity_type is EntityType.IPV4
    assert result.entity_value == "8.8.8.8"


async def test_normalize_accepts_bare_result() -> None:
    result = await make_provider(json_handler(_envelope(_host_result()))).normalize(_host_result())
    assert result.status is ExposureStatus.OK
    assert result.entity_value == "8.8.8.8"


async def test_host_with_no_services_or_hosting_has_no_category() -> None:
    result = _host_result(services=[], autonomous_system=None, location=None, dns=None)
    finding = await make_provider(json_handler(_envelope(result))).lookup(ip_entity("8.8.8.8"))
    assert finding.category is None


# --- non-global IPs short-circuit (no request) ---


async def test_private_ipv4_is_not_found_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_envelope(_host_result()))

    result = await make_provider(handler).lookup(ip_entity("192.168.1.10"))
    assert result.status is ExposureStatus.NOT_FOUND
    assert calls["n"] == 0


async def test_invalid_ip_is_error_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_envelope(_host_result()))

    result = await make_provider(handler).lookup(ip_entity("999.999.999.999"))
    assert result.status is ExposureStatus.ERROR
    assert calls["n"] == 0


async def test_unsupported_entity_makes_no_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_envelope(_host_result()))

    result = await make_provider(handler).lookup(ip_entity("evil.example.com", EntityType.DOMAIN))
    assert result.status is ExposureStatus.UNSUPPORTED
    assert calls["n"] == 0


# --- auth / http failure mapping ---


async def test_missing_credentials_is_unauthorized_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_envelope(_host_result()))

    result = await make_provider(handler, api_id=None, api_secret=None).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.UNAUTHORIZED
    assert calls["n"] == 0


async def test_partial_credentials_is_unauthorized_without_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_envelope(_host_result()))

    result = await make_provider(handler, api_id="id", api_secret=None).lookup(ip_entity("8.8.8.8"))
    assert result.status is ExposureStatus.UNAUTHORIZED
    assert calls["n"] == 0


async def test_401_is_unauthorized() -> None:
    result = await make_provider(json_handler({"error": "Invalid credentials"}, status=401)).lookup(
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
    result = await make_provider(json_handler({"error": "rate limited"}, status=429)).lookup(
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


async def test_missing_result_key_is_error() -> None:
    result = await make_provider(json_handler({"code": 200, "status": "OK"})).lookup(
        ip_entity("8.8.8.8")
    )
    assert result.status is ExposureStatus.ERROR


# --- health() ---


async def test_health_operational_when_reachable_and_authorized() -> None:
    provider = make_provider(json_handler({"email": "a@b.com", "quota": {}}))
    health = await provider.health()
    assert health.status is ExposureProviderStatus.OPERATIONAL


async def test_health_degraded_when_no_credentials() -> None:
    provider = make_provider(json_handler({}), api_id=None, api_secret=None)
    health = await provider.health()
    assert health.status is ExposureProviderStatus.DEGRADED
    assert health.detail == "API credentials not configured"


async def test_health_degraded_on_401() -> None:
    provider = make_provider(json_handler({"error": "Invalid credentials"}, status=401))
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
    provider = CensysProvider(api_id="id", api_secret="secret", enabled=False)
    health = await provider.health()
    assert health.status is ExposureProviderStatus.DISABLED


# --- disabled provider ---


def test_disabled_flag_reflected_in_metadata() -> None:
    provider = CensysProvider(api_id="id", api_secret="secret", enabled=False)
    assert provider.metadata.enabled is False
    assert provider.enabled is False


def test_enabled_flag_from_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CENSYS_ENABLED", "false")
    provider = CensysProvider(api_id="id", api_secret="secret")
    assert provider.metadata.enabled is False


# --- configuration() ---


async def test_configuration_reports_status_without_leaking_credentials() -> None:
    provider = CensysProvider(
        api_id="my-id", api_secret="super-secret", base_url="https://example.test", timeout=5.0
    )
    config = await provider.configuration()
    assert config == {
        "api_credentials_configured": True,
        "base_url": "https://example.test",
        "timeout": 5.0,
        "enabled": True,
    }
    assert "super-secret" not in str(config)
    assert "my-id" not in str(config)


# --- cache ---


async def test_repeat_lookup_is_served_from_cache() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_envelope(_host_result()))

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
        return httpx.Response(200, json=_envelope(_host_result()))

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


async def test_unauthorized_result_is_never_cached_so_fixed_credentials_retry() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": "Invalid credentials"})

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
