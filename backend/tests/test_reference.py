"""Unit tests for the Reference Provider Framework (Phase 1.8).

The framework ships no concrete providers, so these tests define small fake
reference providers to exercise registration, discovery, routing, metadata, and
the stubbed lookup surface. Pure, offline, deterministic.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import ResultStatus
from threatlens.reference import (
    DuplicateReferenceProviderError,
    ReferenceCapability,
    ReferenceMetadata,
    ReferenceProvider,
    ReferenceRegistry,
    ReferenceRouter,
)


def make_provider(
    name: str,
    *,
    types: set[EntityType],
    capabilities: set[ReferenceCapability] | None = None,
    priority: int = 100,
    enabled: bool = True,
    **provenance: object,
) -> ReferenceProvider:
    info = ReferenceMetadata(
        name=name,
        display_name=name.title(),
        supported_entity_types=frozenset(types),
        capabilities=frozenset(capabilities or set()),
        priority=priority,
        enabled=enabled,
        **provenance,  # type: ignore[arg-type]
    )

    class _FakeReferenceProvider(ReferenceProvider):
        @property
        def metadata(self) -> ReferenceMetadata:
            return info

    return _FakeReferenceProvider()


def entity_of(entity_type: EntityType, value: str = "x") -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
    )


def names(providers: tuple[ReferenceProvider, ...]) -> list[str]:
    return [p.name for p in providers]


def sample_registry() -> ReferenceRegistry:
    registry = ReferenceRegistry()
    registry.register(
        make_provider(
            "mitre_attack",
            types={EntityType.MITRE_TECHNIQUE},
            capabilities={ReferenceCapability.TECHNIQUE, ReferenceCapability.TACTIC},
            priority=10,
        )
    )
    registry.register(
        make_provider(
            "nvd",
            types={EntityType.CVE},
            capabilities={ReferenceCapability.VULNERABILITY},
            priority=20,
        )
    )
    return registry


# --- registration / discovery ---


def test_register_and_discover() -> None:
    registry = ReferenceRegistry()
    provider = make_provider("mitre_attack", types={EntityType.MITRE_TECHNIQUE})

    registry.register(provider)

    assert len(registry) == 1
    assert "mitre_attack" in registry
    assert registry.get("mitre_attack") is provider
    assert registry.get("missing") is None
    assert names(registry.providers) == ["mitre_attack"]


def test_duplicate_registration_raises() -> None:
    registry = ReferenceRegistry()
    registry.register(make_provider("nvd", types={EntityType.CVE}))

    with pytest.raises(DuplicateReferenceProviderError) as exc:
        registry.register(make_provider("nvd", types={EntityType.CVE}))

    assert exc.value.name == "nvd"


def test_providers_ordered_by_priority_then_name() -> None:
    registry = ReferenceRegistry()
    registry.register(make_provider("b", types={EntityType.CVE}, priority=20))
    registry.register(make_provider("a", types={EntityType.CVE}, priority=20))
    registry.register(make_provider("first", types={EntityType.CVE}, priority=10))
    assert names(registry.providers) == ["first", "a", "b"]


# --- routing ---


def test_route_by_entity_type() -> None:
    router = ReferenceRouter(sample_registry())
    assert names(router.route(entity_of(EntityType.MITRE_TECHNIQUE, "T1059"))) == ["mitre_attack"]
    assert names(router.route(entity_of(EntityType.CVE, "CVE-2024-3094"))) == ["nvd"]


def test_route_type_matches_route() -> None:
    router = ReferenceRouter(sample_registry())
    by_entity = router.route(entity_of(EntityType.MITRE_TECHNIQUE, "T1059"))
    by_type = router.route_type(EntityType.MITRE_TECHNIQUE)
    assert names(by_entity) == names(by_type) == ["mitre_attack"]


def test_unsupported_entity_routes_to_nothing() -> None:
    router = ReferenceRouter(sample_registry())
    assert router.route(entity_of(EntityType.IPV4, "8.8.8.8")) == ()
    assert router.route_type(EntityType.SHA256) == ()


def test_disabled_provider_is_registered_but_not_routed() -> None:
    registry = sample_registry()
    registry.register(make_provider("disabled", types={EntityType.MITRE_TECHNIQUE}, enabled=False))
    router = ReferenceRouter(registry)
    assert "disabled" in registry
    assert "disabled" not in names(router.route(entity_of(EntityType.MITRE_TECHNIQUE)))


def test_capability_filtering() -> None:
    router = ReferenceRouter(sample_registry())
    assert names(
        router.route(entity_of(EntityType.MITRE_TECHNIQUE), capability=ReferenceCapability.TACTIC)
    ) == ["mitre_attack"]
    assert (
        router.route(entity_of(EntityType.MITRE_TECHNIQUE), capability=ReferenceCapability.WEAKNESS)
        == ()
    )


# --- metadata ---


def test_metadata_provenance_fields() -> None:
    provider = make_provider(
        "mitre_attack",
        types={EntityType.MITRE_TECHNIQUE},
        capabilities={ReferenceCapability.TECHNIQUE},
        dataset_version="v15.1",
        release_date="2024-10-31",
        source_url="https://attack.mitre.org",
        offline=True,
        last_updated=datetime(2024, 11, 1, tzinfo=UTC),
    )
    info = provider.provider_info()
    assert info.dataset_version == "v15.1"
    assert info.release_date == "2024-10-31"
    assert info.offline is True
    assert info.last_updated is not None
    assert provider.supports(EntityType.MITRE_TECHNIQUE)
    assert not provider.supports(EntityType.CVE)
    assert provider.has_capability(ReferenceCapability.TECHNIQUE)
    assert not provider.has_capability(ReferenceCapability.VULNERABILITY)


def test_metadata_requires_at_least_one_entity_type() -> None:
    with pytest.raises(ValueError):
        ReferenceMetadata(name="empty", display_name="Empty", supported_entity_types=frozenset())


# --- registry isolation / extensibility ---


def test_registries_are_isolated() -> None:
    a = ReferenceRegistry()
    b = ReferenceRegistry()
    a.register(make_provider("mitre_attack", types={EntityType.MITRE_TECHNIQUE}))
    assert "mitre_attack" in a
    assert "mitre_attack" not in b
    assert len(b) == 0


def test_new_provider_routes_without_router_changes() -> None:
    # Extensibility: a brand-new provider for a new entity type just works.
    registry = sample_registry()
    registry.register(
        make_provider(
            "capec",
            types={EntityType.MITRE_TECHNIQUE},  # stand-in until a CAPEC type exists
            capabilities={ReferenceCapability.ATTACK_PATTERN},
            priority=30,
        )
    )
    router = ReferenceRouter(registry)
    routed = names(router.route(entity_of(EntityType.MITRE_TECHNIQUE)))
    assert routed == ["mitre_attack", "capec"]


# --- stubbed lookup surface ---


def test_lookup_and_normalize_are_stubbed() -> None:
    provider = make_provider("mitre_attack", types={EntityType.MITRE_TECHNIQUE})
    with pytest.raises(NotImplementedError):
        asyncio.run(provider.lookup(entity_of(EntityType.MITRE_TECHNIQUE)))
    with pytest.raises(NotImplementedError):
        asyncio.run(provider.normalize({}))


def test_safe_lookup_converts_errors_to_failures() -> None:
    # The fake provider inherits the raising lookup() stub; safe_lookup must
    # convert that into a structured failure (never reputation) instead of raising.
    provider = make_provider("mitre_attack", types={EntityType.MITRE_TECHNIQUE})
    result = asyncio.run(provider.safe_lookup(entity_of(EntityType.MITRE_TECHNIQUE, "T1059")))
    assert result.status is ResultStatus.ERROR
    assert result.provider == "mitre_attack"
    assert result.reputation is None
