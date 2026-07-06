"""Tests for IdentityRegistry: registration, discovery, and routing."""

from __future__ import annotations

import pytest

from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.identity.exceptions import DuplicateIdentityProviderError
from threatlens.identity.models import IdentityCapability, IdentityProviderMetadata
from threatlens.identity.provider import IdentityProvider
from threatlens.identity.registry import IdentityRegistry, build_default_registry


def _entity(entity_type: EntityType = EntityType.EMAIL, value: str = "a@b.com") -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=95,
        validation=ValidationStatus.VALID,
        possible_matches=[],
        routing=RoutingMetadata(providers=[]),
    )


class _FakeProvider(IdentityProvider):
    def __init__(
        self,
        name: str,
        *,
        entity_types: frozenset[EntityType] = frozenset({EntityType.EMAIL}),
        capabilities: frozenset[IdentityCapability] = frozenset({IdentityCapability.BREACHES}),
        priority: int = 100,
        enabled: bool = True,
    ) -> None:
        self._meta = IdentityProviderMetadata(
            name=name,
            display_name=name.title(),
            supported_entity_types=entity_types,
            capabilities=capabilities,
            priority=priority,
            enabled=enabled,
        )

    @property
    def metadata(self) -> IdentityProviderMetadata:
        return self._meta


class TestRegistration:
    def test_register_and_get(self) -> None:
        registry = IdentityRegistry()
        provider = _FakeProvider("hibp")
        registry.register(provider)
        assert registry.get("hibp") is provider
        assert "hibp" in registry
        assert len(registry) == 1

    def test_duplicate_name_raises(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeProvider("hibp"))
        with pytest.raises(DuplicateIdentityProviderError):
            registry.register(_FakeProvider("hibp"))

    def test_get_missing_returns_none(self) -> None:
        registry = IdentityRegistry()
        assert registry.get("nope") is None

    def test_providers_ordered_by_priority_then_name(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeProvider("z_provider", priority=50))
        registry.register(_FakeProvider("a_provider", priority=50))
        registry.register(_FakeProvider("early", priority=10))
        names = [p.name for p in registry.providers]
        assert names == ["early", "a_provider", "z_provider"]


class TestRouting:
    def test_routes_by_supported_entity_type(self) -> None:
        registry = IdentityRegistry()
        email_provider = _FakeProvider("email_only", entity_types=frozenset({EntityType.EMAIL}))
        domain_provider = _FakeProvider("domain_only", entity_types=frozenset({EntityType.DOMAIN}))
        registry.register(email_provider)
        registry.register(domain_provider)

        routed = registry.route(_entity(EntityType.EMAIL))
        assert routed == (email_provider,)

    def test_disabled_provider_excluded_from_routing(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeProvider("disabled", enabled=False))
        assert registry.route(_entity()) == ()

    def test_capability_narrows_routing(self) -> None:
        registry = IdentityRegistry()
        breaches = _FakeProvider("breaches", capabilities=frozenset({IdentityCapability.BREACHES}))
        directory = _FakeProvider(
            "directory", capabilities=frozenset({IdentityCapability.DIRECTORY_PROFILE})
        )
        registry.register(breaches)
        registry.register(directory)

        routed = registry.route(_entity(), capability=IdentityCapability.DIRECTORY_PROFILE)
        assert routed == (directory,)

    def test_route_type_matches_route(self) -> None:
        registry = IdentityRegistry()
        provider = _FakeProvider("hibp")
        registry.register(provider)
        entity = _entity()
        assert registry.route(entity) == registry.route_type(entity.type)

    def test_empty_registry_routes_to_nothing(self) -> None:
        registry = IdentityRegistry()
        assert registry.route(_entity()) == ()


def test_build_default_registry_is_empty() -> None:
    """Phase 6.0 ships zero providers; the default registry reflects that."""
    registry = build_default_registry()
    assert len(registry) == 0
    assert registry.providers == ()
