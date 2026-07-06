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
from threatlens.identity.registry import IdentityRegistry, build_default_registry
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
    @property
    def metadata(self) -> IdentityProviderMetadata:
        return IdentityProviderMetadata(
            name="fake_ok",
            display_name="Fake OK",
            supported_entity_types=frozenset({EntityType.EMAIL}),
            capabilities=frozenset({IdentityCapability.BREACHES}),
        )

    async def lookup(self, entity: Entity) -> IdentityFinding:
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
        service = IdentityService(build_default_registry())
        summary = await service.investigate(_entity())
        assert summary.findings == []
        assert summary.statistics.providers_queried == 0
        assert summary.metadata.framework_version == IDENTITY_FRAMEWORK_VERSION

    async def test_entity_type_and_value_are_preserved(self) -> None:
        service = IdentityService(build_default_registry())
        summary = await service.investigate(_entity(EntityType.DOMAIN, "example.com"))
        assert summary.entity_type == EntityType.DOMAIN
        assert summary.entity_value == "example.com"

    async def test_default_registry_frozen_version_is_pre_1_0(self) -> None:
        # Framework-only phase: version stays pre-1.0 until providers are validated.
        assert IDENTITY_FRAMEWORK_VERSION == "0.1.0"


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
