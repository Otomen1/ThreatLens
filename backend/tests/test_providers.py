"""Unit tests for the Intelligence Provider Framework (Phase 1.2).

The framework ships with no concrete providers, so these tests define small fake
providers to exercise registration and routing. Everything here is deterministic
and offline — no network, no credentials.
"""

from __future__ import annotations

import asyncio

import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import (
    DuplicateProviderError,
    IntelligenceProvider,
    ProviderAuthType,
    ProviderCapability,
    ProviderMetadata,
    ProviderRegistry,
    ProviderRouter,
    ProviderStatus,
)


def make_provider(
    name: str,
    *,
    types: set[EntityType],
    capabilities: set[ProviderCapability] | None = None,
    priority: int = 100,
    enabled: bool = True,
    auth: ProviderAuthType = ProviderAuthType.API_KEY,
) -> IntelligenceProvider:
    """Build a fake provider described entirely by its metadata."""

    info = ProviderMetadata(
        name=name,
        display_name=name.title(),
        supported_entity_types=frozenset(types),
        capabilities=frozenset(capabilities or set()),
        priority=priority,
        enabled=enabled,
        auth_type=auth,
    )

    class _FakeProvider(IntelligenceProvider):
        @property
        def metadata(self) -> ProviderMetadata:
            return info

    return _FakeProvider()


def entity_of(entity_type: EntityType, value: str = "x") -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
    )


# --- a small provider set mirroring the routing examples in the spec ---


def sample_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(
        make_provider(
            "virustotal",
            types={
                EntityType.IPV4,
                EntityType.DOMAIN,
                EntityType.URL,
                EntityType.MD5,
                EntityType.SHA1,
                EntityType.SHA256,
            },
            capabilities={
                ProviderCapability.REPUTATION,
                ProviderCapability.MALWARE_ANALYSIS,
            },
            priority=10,
        )
    )
    registry.register(
        make_provider(
            "abuseipdb",
            types={EntityType.IPV4},
            capabilities={ProviderCapability.REPUTATION, ProviderCapability.BLOCKLIST},
            priority=20,
        )
    )
    registry.register(
        make_provider(
            "malwarebazaar",
            types={EntityType.MD5, EntityType.SHA1, EntityType.SHA256},
            capabilities={
                ProviderCapability.MALWARE_ANALYSIS,
                ProviderCapability.SAMPLE_RETRIEVAL,
            },
            priority=20,
        )
    )
    registry.register(
        make_provider(
            "otx",
            types={
                EntityType.IPV4,
                EntityType.DOMAIN,
                EntityType.URL,
                EntityType.SHA256,
            },
            capabilities={ProviderCapability.THREAT_CONTEXT},
            priority=30,
        )
    )
    return registry


def names(providers: tuple[IntelligenceProvider, ...]) -> list[str]:
    return [p.name for p in providers]


# --- registration ---


def test_register_and_retrieve_provider() -> None:
    registry = ProviderRegistry()
    provider = make_provider("virustotal", types={EntityType.IPV4})

    registry.register(provider)

    assert len(registry) == 1
    assert "virustotal" in registry
    assert registry.get("virustotal") is provider
    assert registry.get("missing") is None
    assert names(registry.providers) == ["virustotal"]


def test_duplicate_registration_raises() -> None:
    registry = ProviderRegistry()
    registry.register(make_provider("virustotal", types={EntityType.IPV4}))

    with pytest.raises(DuplicateProviderError) as exc:
        registry.register(make_provider("virustotal", types={EntityType.DOMAIN}))

    assert exc.value.name == "virustotal"


def test_providers_are_ordered_by_priority_then_name() -> None:
    registry = sample_registry()
    # priority 10, then the two priority-20 providers alphabetically, then 30.
    assert names(registry.providers) == [
        "virustotal",
        "abuseipdb",
        "malwarebazaar",
        "otx",
    ]


# --- entity routing ---


def test_route_ipv4_returns_capable_providers_in_priority_order() -> None:
    router = ProviderRouter(sample_registry())
    routed = router.route(entity_of(EntityType.IPV4, "8.8.8.8"))
    assert names(routed) == ["virustotal", "abuseipdb", "otx"]


def test_route_sha256_returns_capable_providers_in_priority_order() -> None:
    router = ProviderRouter(sample_registry())
    routed = router.route(entity_of(EntityType.SHA256, "a" * 64))
    assert names(routed) == ["virustotal", "malwarebazaar", "otx"]


def test_route_type_matches_route_on_entity() -> None:
    router = ProviderRouter(sample_registry())
    by_entity = router.route(entity_of(EntityType.DOMAIN, "example.com"))
    by_type = router.route_type(EntityType.DOMAIN)
    assert names(by_entity) == names(by_type) == ["virustotal", "otx"]


# --- unsupported entities ---


def test_unsupported_entity_routes_to_nothing() -> None:
    router = ProviderRouter(sample_registry())
    assert router.route(entity_of(EntityType.MITRE_TECHNIQUE, "T1059")) == ()
    assert router.route_type(EntityType.REGISTRY_KEY) == ()


def test_empty_registry_routes_to_nothing() -> None:
    router = ProviderRouter(ProviderRegistry())
    assert router.route(entity_of(EntityType.IPV4)) == ()


# --- capability matching ---


def test_route_filtered_by_capability() -> None:
    router = ProviderRouter(sample_registry())

    reputation = router.route(
        entity_of(EntityType.IPV4), capability=ProviderCapability.REPUTATION
    )
    assert names(reputation) == ["virustotal", "abuseipdb"]

    samples = router.route_type(
        EntityType.SHA256, capability=ProviderCapability.SAMPLE_RETRIEVAL
    )
    assert names(samples) == ["malwarebazaar"]


def test_capability_with_no_matching_provider_is_empty() -> None:
    router = ProviderRouter(sample_registry())
    routed = router.route_type(
        EntityType.IPV4, capability=ProviderCapability.SAMPLE_RETRIEVAL
    )
    assert routed == ()


def test_has_capability_and_supports() -> None:
    provider = make_provider(
        "vt",
        types={EntityType.IPV4},
        capabilities={ProviderCapability.REPUTATION},
    )
    assert provider.supports(EntityType.IPV4) is True
    assert provider.supports(EntityType.DOMAIN) is False
    assert provider.has_capability(ProviderCapability.REPUTATION) is True
    assert provider.has_capability(ProviderCapability.WHOIS) is False


# --- disabled providers ---


def test_disabled_provider_is_registered_but_not_routed() -> None:
    registry = sample_registry()
    registry.register(
        make_provider("disabled-vt", types={EntityType.IPV4}, enabled=False)
    )
    router = ProviderRouter(registry)

    # Still present in the registry...
    assert "disabled-vt" in registry
    # ...but excluded from routing.
    assert "disabled-vt" not in names(router.route(entity_of(EntityType.IPV4)))


def test_disabling_the_only_provider_yields_no_route() -> None:
    registry = ProviderRegistry()
    registry.register(
        make_provider("solo", types={EntityType.DOMAIN}, enabled=False)
    )
    router = ProviderRouter(registry)
    assert router.route_type(EntityType.DOMAIN) == ()


# --- metadata + stubbed async surface ---


def test_requires_auth_reflects_auth_type() -> None:
    keyed = make_provider("k", types={EntityType.IPV4}, auth=ProviderAuthType.API_KEY)
    open_ = make_provider("o", types={EntityType.IPV4}, auth=ProviderAuthType.NONE)
    assert keyed.metadata.requires_auth is True
    assert open_.metadata.requires_auth is False


def test_metadata_requires_at_least_one_entity_type() -> None:
    with pytest.raises(ValueError):
        ProviderMetadata(
            name="empty",
            display_name="Empty",
            supported_entity_types=frozenset(),
        )


def test_provider_info_returns_metadata() -> None:
    provider = make_provider("vt", types={EntityType.IPV4})
    assert provider.provider_info() is provider.metadata
    assert provider.provider_info().name == "vt"


def test_health_reports_status_without_network() -> None:
    enabled = make_provider("a", types={EntityType.IPV4})
    disabled = make_provider("b", types={EntityType.IPV4}, enabled=False)
    assert asyncio.run(enabled.health()).status == ProviderStatus.UNKNOWN
    assert asyncio.run(disabled.health()).status == ProviderStatus.DISABLED


def test_search_and_normalize_are_stubbed() -> None:
    provider = make_provider("vt", types={EntityType.IPV4})
    with pytest.raises(NotImplementedError):
        asyncio.run(provider.search(entity_of(EntityType.IPV4)))
    with pytest.raises(NotImplementedError):
        asyncio.run(provider.normalize({}))
