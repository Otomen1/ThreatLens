"""Tests for IdentityService — the real aggregation path, with and without providers."""

from __future__ import annotations

from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.identity.models import (
    IdentityAsset,
    IdentityCapability,
    IdentityFinding,
    IdentityProviderMetadata,
    IdentityStatus,
)
from threatlens.identity.provider import IdentityProvider
from threatlens.identity.registry import IdentityRegistry
from threatlens.identity.service import IDENTITY_FRAMEWORK_VERSION, IdentityService


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


class _FakeOkProvider(IdentityProvider):
    def __init__(self) -> None:
        self.calls = 0

    @property
    def metadata(self) -> IdentityProviderMetadata:
        return IdentityProviderMetadata(
            name="fake_ok",
            display_name="Fake OK",
            supported_entity_types=frozenset({EntityType.EMAIL}),
            capabilities=frozenset({IdentityCapability.BREACHES}),
        )

    async def lookup(self, entity: Entity) -> IdentityFinding:
        self.calls += 1
        return IdentityFinding(
            provider=self.name,
            provider_display_name=self.metadata.display_name,
            entity_type=entity.type,
            entity_value=entity.value,
            status=IdentityStatus.OK,
            category=IdentityCapability.BREACHES,
            summary="1 breach",
            assets=[IdentityAsset(asset_type="breached_account", value=entity.value)],
        )


class _FakeFailingProvider(IdentityProvider):
    @property
    def metadata(self) -> IdentityProviderMetadata:
        return IdentityProviderMetadata(
            name="fake_failing",
            display_name="Fake Failing",
            supported_entity_types=frozenset({EntityType.EMAIL}),
        )

    async def lookup(self, entity: Entity) -> IdentityFinding:
        raise RuntimeError("simulated outage")


class TestEmptyRegistry:
    async def test_investigate_returns_well_formed_empty_summary(self) -> None:
        service = IdentityService(IdentityRegistry())
        summary = await service.investigate(_entity())
        assert summary.findings == []
        assert summary.statistics.providers_queried == 0
        assert summary.metadata.framework_version == IDENTITY_FRAMEWORK_VERSION

    async def test_entity_type_and_value_are_preserved(self) -> None:
        service = IdentityService(IdentityRegistry())
        summary = await service.investigate(_entity(EntityType.DOMAIN, "example.com"))
        assert summary.entity_type == EntityType.DOMAIN
        assert summary.entity_value == "example.com"

    async def test_identity_provider_version_is_stable(self) -> None:
        assert IDENTITY_FRAMEWORK_VERSION == "1.0.0"


class TestWithProviders:
    async def test_ok_provider_contributes_findings(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeOkProvider())
        service = IdentityService(registry)

        summary = await service.investigate(_entity())

        assert summary.statistics.providers_queried == 1
        assert summary.statistics.providers_ok == 1
        assert summary.statistics.total_assets == 1
        assert summary.has_findings is True

    async def test_failing_provider_never_blocks_or_raises(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeOkProvider())
        registry.register(_FakeFailingProvider())
        service = IdentityService(registry)

        summary = await service.investigate(_entity())

        assert summary.statistics.providers_queried == 2
        assert summary.statistics.providers_ok == 1  # only the OK provider
        assert summary.statistics.total_assets == 1  # the failing one contributes nothing

    async def test_unsupported_entity_type_routes_to_nothing(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeOkProvider())  # only supports EMAIL
        service = IdentityService(registry)

        summary = await service.investigate(_entity(EntityType.IPV4, "8.8.8.8"))

        assert summary.statistics.providers_queried == 0

    async def test_investigate_is_deterministic(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeOkProvider())
        service = IdentityService(registry)

        first = await service.investigate(_entity())
        second = await service.investigate(_entity())
        # Everything but the wall-clock generated_at must be identical.
        assert first.model_dump(exclude={"metadata"}) == second.model_dump(exclude={"metadata"})
        assert [f.provider for f in first.findings] == [f.provider for f in second.findings]

    async def test_success_is_cached_and_refresh_bypasses_cache(self) -> None:
        registry = IdentityRegistry()
        provider = _FakeOkProvider()
        registry.register(provider)
        service = IdentityService(registry)

        _, first_cached = await service.investigate_with_cache_state(_entity())
        _, second_cached = await service.investigate_with_cache_state(_entity())
        _, refresh_cached = await service.investigate_with_cache_state(_entity(), refresh=True)

        assert first_cached is False
        assert second_cached is True
        assert refresh_cached is False
        assert provider.calls == 2

    async def test_failures_are_not_cached(self) -> None:
        registry = IdentityRegistry()
        registry.register(_FakeFailingProvider())
        service = IdentityService(registry)

        _, first_cached = await service.investigate_with_cache_state(_entity())
        _, second_cached = await service.investigate_with_cache_state(_entity())

        assert first_cached is False
        assert second_cached is False
