"""Deterministic, in-process fake providers for the Exposure validation corpus.

No network, no real provider — a canned :class:`ExposureFinding` (or a raised
exception, for the provider-crash safety case) returned from ``lookup()``, so
the corpus can construct any provider-combination/status-mix scenario without
HTTP mocking. Real per-provider correctness (Shodan/Censys/GreyNoise parsing,
auth, HTTP status mapping) is already covered by
``tests/exposure/test_*_provider.py``; this package validates the
**framework's** routing/merge/ordering/determinism across provider
combinations, so fakes use the real provider names (``shodan``, ``censys``,
``greynoise``) to exercise the real priority-then-name ordering tiebreak,
while their finding content is entirely canned.

Every canned finding uses a fixed ``fetched_at`` (never ``datetime.now()``),
so the only wall-clock-derived field anywhere in a scenario's
``ExposureSummary`` is ``metadata.generated_at`` — set by
``ExposureService.investigate()`` itself, which takes no injectable clock (a
documented, pre-existing limitation; see the Phase 5.4 architecture review).
"""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.exposure.models import (
    ExposureAsset,
    ExposureCapability,
    ExposureEvidence,
    ExposureFinding,
    ExposureProviderHealth,
    ExposureProviderMetadata,
    ExposureProviderStatus,
    ExposureReference,
    ExposureStatus,
)
from threatlens.exposure.provider import ExposureProvider

FIXED_TIME = datetime(2024, 1, 1, tzinfo=UTC)

_DEFAULT_TYPES = frozenset({EntityType.IPV4, EntityType.IPV6})


def entity(value: str, entity_type: EntityType = EntityType.IPV4) -> Entity:
    """Build an already-detected, valid :class:`Entity` for a corpus scenario."""
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=95,
        validation=ValidationStatus.VALID,
        possible_matches=[],
        routing=RoutingMetadata(providers=[]),
    )


class FakeExposureProvider(ExposureProvider):
    """A controllable provider: returns a canned finding, or raises, on lookup."""

    def __init__(
        self,
        name: str,
        *,
        display_name: str | None = None,
        entity_types: frozenset[EntityType] = _DEFAULT_TYPES,
        capabilities: frozenset[ExposureCapability] = frozenset({ExposureCapability.OPEN_PORTS}),
        priority: int = 100,
        enabled: bool = True,
        finding: ExposureFinding | None = None,
        raises: Exception | None = None,
        health_status: ExposureProviderStatus = ExposureProviderStatus.OPERATIONAL,
    ) -> None:
        self._meta = ExposureProviderMetadata(
            name=name,
            display_name=display_name or name.title(),
            supported_entity_types=entity_types,
            capabilities=capabilities,
            priority=priority,
            enabled=enabled,
        )
        self._finding = finding
        self._raises = raises
        self._health_status = health_status

    @property
    def metadata(self) -> ExposureProviderMetadata:
        return self._meta

    async def lookup(self, entity: Entity) -> ExposureFinding:
        if self._raises is not None:
            raise self._raises
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)
        assert self._finding is not None, f"{self.name}: no canned finding configured"
        return self._finding

    async def health(self) -> ExposureProviderHealth:
        return ExposureProviderHealth(name=self.name, status=self._health_status)


# --------------------------------------------------------------------------- #
# Canned finding builders (fixed timestamps; no randomness)
# --------------------------------------------------------------------------- #


def ok_finding(
    provider: str,
    *,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "192.0.2.1",
    category: ExposureCapability | None = ExposureCapability.OPEN_PORTS,
    evidence: tuple[ExposureEvidence, ...] = (),
    assets: tuple[ExposureAsset, ...] = (),
    references: tuple[ExposureReference, ...] = (),
) -> ExposureFinding:
    """A successful finding with at least one evidence/asset by default."""
    if not evidence and not assets:
        evidence = (ExposureEvidence(type="fact", summary=f"{provider}: synthetic fact"),)
    return ExposureFinding(
        provider=provider,
        provider_display_name=provider.title(),
        entity_type=entity_type,
        entity_value=entity_value,
        status=ExposureStatus.OK,
        category=category,
        summary=f"{provider}: synthetic finding",
        evidence=list(evidence),
        assets=list(assets),
        references=list(references),
        fetched_at=FIXED_TIME,
    )


def not_found_finding(
    provider: str, *, entity_type: EntityType = EntityType.IPV4, entity_value: str = "192.0.2.1"
) -> ExposureFinding:
    return ExposureFinding.not_found(
        provider=provider,
        provider_display_name=provider.title(),
        entity_type=entity_type,
        entity_value=entity_value,
    )


def unsupported_finding(
    provider: str, *, entity_type: EntityType = EntityType.IPV4, entity_value: str = "192.0.2.1"
) -> ExposureFinding:
    return ExposureFinding.unsupported(
        provider=provider,
        provider_display_name=provider.title(),
        entity_type=entity_type,
        entity_value=entity_value,
    )


def failure_finding(
    provider: str,
    status: ExposureStatus,
    message: str,
    *,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "192.0.2.1",
    retryable: bool = False,
) -> ExposureFinding:
    return ExposureFinding.failure(
        provider=provider,
        provider_display_name=provider.title(),
        entity_type=entity_type,
        entity_value=entity_value,
        message=message,
        status=status,
        retryable=retryable,
    )
