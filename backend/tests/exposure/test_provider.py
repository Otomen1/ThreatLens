"""Tests for the ExposureProvider abstract base (stub behavior only — Phase 5.0)."""

from __future__ import annotations

import pytest

from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.models import (
    ExposureCapability,
    ExposureProviderMetadata,
    ExposureProviderStatus,
)
from threatlens.exposure.provider import ExposureProvider


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


class _StubProvider(ExposureProvider):
    """A minimal concrete provider exercising only the base class's stubs."""

    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = enabled

    @property
    def metadata(self) -> ExposureProviderMetadata:
        return ExposureProviderMetadata(
            name="stub",
            display_name="Stub",
            supported_entity_types=frozenset({EntityType.IPV4}),
            capabilities=frozenset({ExposureCapability.OPEN_PORTS}),
            enabled=self._enabled,
        )


class _RaisingProvider(ExposureProvider):
    """A provider whose ``lookup`` always raises, exercising ``safe_lookup``."""

    @property
    def metadata(self) -> ExposureProviderMetadata:
        return ExposureProviderMetadata(
            name="raiser",
            display_name="Raiser",
            supported_entity_types=frozenset({EntityType.IPV4}),
        )

    async def lookup(self, entity: Entity) -> object:  # type: ignore[override]
        raise RuntimeError("network exploded")


class TestAccessors:
    def test_name_priority_enabled_from_metadata(self) -> None:
        provider = _StubProvider()
        assert provider.name == "stub"
        assert provider.priority == 100
        assert provider.enabled is True

    def test_supports_and_has_capability(self) -> None:
        provider = _StubProvider()
        assert provider.supports(EntityType.IPV4) is True
        assert provider.supports(EntityType.EMAIL) is False
        assert provider.has_capability(ExposureCapability.OPEN_PORTS) is True
        assert provider.has_capability(ExposureCapability.BREACHES) is False


class TestHealth:
    async def test_enabled_provider_reports_unknown(self) -> None:
        health = await _StubProvider(enabled=True).health()
        assert health.status == ExposureProviderStatus.UNKNOWN

    async def test_disabled_provider_reports_disabled(self) -> None:
        health = await _StubProvider(enabled=False).health()
        assert health.status == ExposureProviderStatus.DISABLED


class TestUnimplementedStubs:
    async def test_lookup_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            await _StubProvider().lookup(_entity())

    async def test_normalize_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            await _StubProvider().normalize({"raw": "payload"})

    async def test_configuration_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            await _StubProvider().configuration()


class TestSafeLookup:
    async def test_wraps_unexpected_exception_into_a_failed_finding(self) -> None:
        finding = await _RaisingProvider().safe_lookup(_entity())
        assert finding.is_error is True
        assert finding.error is not None
        assert "network exploded" in (finding.error.detail or "")

    async def test_never_raises(self) -> None:
        # The whole point of safe_lookup: a buggy provider never propagates.
        result = await _RaisingProvider().safe_lookup(_entity())
        assert result is not None
