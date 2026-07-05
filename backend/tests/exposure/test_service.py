"""Tests for ExposureService — the real aggregation path, with and without providers."""

from __future__ import annotations

from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.models import (
    ExposureAsset,
    ExposureCapability,
    ExposureFinding,
    ExposureProviderMetadata,
    ExposureStatus,
)
from threatlens.exposure.provider import ExposureProvider
from threatlens.exposure.registry import ExposureRegistry, build_default_registry
from threatlens.exposure.service import EXPOSURE_FRAMEWORK_VERSION, ExposureService


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


class _FakeOkProvider(ExposureProvider):
    @property
    def metadata(self) -> ExposureProviderMetadata:
        return ExposureProviderMetadata(
            name="fake_ok",
            display_name="Fake OK",
            supported_entity_types=frozenset({EntityType.IPV4}),
            capabilities=frozenset({ExposureCapability.OPEN_PORTS}),
        )

    async def lookup(self, entity: Entity) -> ExposureFinding:
        return ExposureFinding(
            provider=self.name,
            provider_display_name=self.metadata.display_name,
            entity_type=entity.type,
            entity_value=entity.value,
            status=ExposureStatus.OK,
            category=ExposureCapability.OPEN_PORTS,
            summary="1 open port",
            assets=[ExposureAsset(asset_type="open_port", value="22")],
        )


class _FakeFailingProvider(ExposureProvider):
    @property
    def metadata(self) -> ExposureProviderMetadata:
        return ExposureProviderMetadata(
            name="fake_failing",
            display_name="Fake Failing",
            supported_entity_types=frozenset({EntityType.IPV4}),
        )

    async def lookup(self, entity: Entity) -> ExposureFinding:
        raise RuntimeError("simulated outage")


class TestEmptyRegistry:
    async def test_investigate_returns_well_formed_empty_summary(self) -> None:
        service = ExposureService(ExposureRegistry())
        summary = await service.investigate(_entity())
        assert summary.findings == []
        assert summary.statistics.providers_queried == 0
        assert summary.metadata.framework_version == EXPOSURE_FRAMEWORK_VERSION

    async def test_entity_type_and_value_are_preserved(self) -> None:
        service = ExposureService(ExposureRegistry())
        summary = await service.investigate(_entity(EntityType.DOMAIN, "evil.example.com"))
        assert summary.entity_type == EntityType.DOMAIN
        assert summary.entity_value == "evil.example.com"


class TestDefaultRegistry:
    """Phase 5.1 added Shodan; Phase 5.2 adds Censys — both real providers."""

    async def test_ipv4_routes_to_both_shodan_and_censys(self) -> None:
        """Framework validation: two real providers merge with zero service.py changes."""
        service = ExposureService(build_default_registry())
        summary = await service.investigate(_entity())
        assert summary.statistics.providers_queried == 2
        assert [f.provider for f in summary.findings] == ["censys", "shodan"]

    async def test_unsupported_entity_type_still_routes_to_nothing(self) -> None:
        service = ExposureService(build_default_registry())
        summary = await service.investigate(_entity(EntityType.DOMAIN, "evil.example.com"))
        assert summary.statistics.providers_queried == 0
        assert summary.entity_type == EntityType.DOMAIN


class TestWithProviders:
    async def test_ok_provider_contributes_findings(self) -> None:
        registry = ExposureRegistry()
        registry.register(_FakeOkProvider())
        service = ExposureService(registry)

        summary = await service.investigate(_entity())

        assert summary.statistics.providers_queried == 1
        assert summary.statistics.providers_ok == 1
        assert summary.statistics.total_assets == 1
        assert summary.has_findings is True

    async def test_failing_provider_never_blocks_or_raises(self) -> None:
        registry = ExposureRegistry()
        registry.register(_FakeOkProvider())
        registry.register(_FakeFailingProvider())
        service = ExposureService(registry)

        summary = await service.investigate(_entity())

        assert summary.statistics.providers_queried == 2
        assert summary.statistics.providers_ok == 1  # only the OK provider
        assert summary.statistics.total_assets == 1  # the failing one contributes nothing

    async def test_unsupported_entity_type_routes_to_nothing(self) -> None:
        registry = ExposureRegistry()
        registry.register(_FakeOkProvider())  # only supports IPV4
        service = ExposureService(registry)

        summary = await service.investigate(_entity(EntityType.EMAIL, "a@b.com"))

        assert summary.statistics.providers_queried == 0
