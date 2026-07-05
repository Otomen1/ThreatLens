"""Tests for ExposureRegistry: registration, discovery, and routing."""

from __future__ import annotations

import pytest

from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.exceptions import DuplicateExposureProviderError
from threatlens.exposure.models import ExposureCapability, ExposureProviderMetadata
from threatlens.exposure.provider import ExposureProvider
from threatlens.exposure.registry import ExposureRegistry, build_default_registry


def _entity(entity_type: EntityType = EntityType.IPV4, value: str = "8.8.8.8") -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=95,
        validation=ValidationStatus.VALID,
        possible_matches=[],
        routing=RoutingMetadata(providers=[]),
    )


class _FakeProvider(ExposureProvider):
    def __init__(
        self,
        name: str,
        *,
        entity_types: frozenset[EntityType] = frozenset({EntityType.IPV4}),
        capabilities: frozenset[ExposureCapability] = frozenset({ExposureCapability.OPEN_PORTS}),
        priority: int = 100,
        enabled: bool = True,
    ) -> None:
        self._meta = ExposureProviderMetadata(
            name=name,
            display_name=name.title(),
            supported_entity_types=entity_types,
            capabilities=capabilities,
            priority=priority,
            enabled=enabled,
        )

    @property
    def metadata(self) -> ExposureProviderMetadata:
        return self._meta


class TestRegistration:
    def test_register_and_get(self) -> None:
        registry = ExposureRegistry()
        provider = _FakeProvider("shodan")
        registry.register(provider)
        assert registry.get("shodan") is provider
        assert "shodan" in registry
        assert len(registry) == 1

    def test_duplicate_name_raises(self) -> None:
        registry = ExposureRegistry()
        registry.register(_FakeProvider("shodan"))
        with pytest.raises(DuplicateExposureProviderError):
            registry.register(_FakeProvider("shodan"))

    def test_get_missing_returns_none(self) -> None:
        registry = ExposureRegistry()
        assert registry.get("nope") is None

    def test_providers_ordered_by_priority_then_name(self) -> None:
        registry = ExposureRegistry()
        registry.register(_FakeProvider("z_provider", priority=50))
        registry.register(_FakeProvider("a_provider", priority=50))
        registry.register(_FakeProvider("early", priority=10))
        names = [p.name for p in registry.providers]
        assert names == ["early", "a_provider", "z_provider"]


class TestRouting:
    def test_routes_by_supported_entity_type(self) -> None:
        registry = ExposureRegistry()
        ip_provider = _FakeProvider("ip_only", entity_types=frozenset({EntityType.IPV4}))
        email_provider = _FakeProvider("email_only", entity_types=frozenset({EntityType.EMAIL}))
        registry.register(ip_provider)
        registry.register(email_provider)

        routed = registry.route(_entity(EntityType.IPV4))
        assert routed == (ip_provider,)

    def test_disabled_provider_excluded_from_routing(self) -> None:
        registry = ExposureRegistry()
        registry.register(_FakeProvider("disabled", enabled=False))
        assert registry.route(_entity()) == ()

    def test_capability_narrows_routing(self) -> None:
        registry = ExposureRegistry()
        ports = _FakeProvider("ports", capabilities=frozenset({ExposureCapability.OPEN_PORTS}))
        breaches = _FakeProvider("breaches", capabilities=frozenset({ExposureCapability.BREACHES}))
        registry.register(ports)
        registry.register(breaches)

        routed = registry.route(_entity(), capability=ExposureCapability.BREACHES)
        assert routed == (breaches,)

    def test_route_type_matches_route(self) -> None:
        registry = ExposureRegistry()
        provider = _FakeProvider("shodan")
        registry.register(provider)
        entity = _entity()
        assert registry.route(entity) == registry.route_type(entity.type)

    def test_empty_registry_routes_to_nothing(self) -> None:
        registry = ExposureRegistry()
        assert registry.route(_entity()) == ()


def test_build_default_registry_registers_shodan_and_censys() -> None:
    """Phase 5.1 registered Shodan; Phase 5.2 adds Censys — both by default."""
    registry = build_default_registry()
    assert len(registry) == 2
    # Both default to priority=100, so the existing priority-then-name
    # tiebreak (no new ordering logic) makes this deterministic.
    assert [provider.name for provider in registry.providers] == ["censys", "shodan"]
