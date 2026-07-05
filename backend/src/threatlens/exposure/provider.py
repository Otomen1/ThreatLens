"""The exposure-provider interface (Phase 5.0 — framework only).

Mirrors ``providers/base.py``: a provider declares static
:class:`ExposureProviderMetadata` and the framework handles registration and
routing. The only abstract member is ``metadata``. The network-touching
methods (``lookup``, ``normalize``, ``configuration``) are stubbed here;
concrete providers implement them in a later phase (5.1+) without changing
this contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..entities.models import Entity
from ..entities.types import EntityType
from .models import (
    ExposureCapability,
    ExposureFinding,
    ExposureProviderHealth,
    ExposureProviderMetadata,
    ExposureProviderStatus,
    ExposureStatus,
)


class ExposureProvider(ABC):
    """Base class for all exposure providers."""

    @property
    @abstractmethod
    def metadata(self) -> ExposureProviderMetadata:
        """Static description of this provider (name, types, capabilities, …)."""

    # --- convenience accessors derived from metadata ---

    @property
    def name(self) -> str:
        """The provider's machine identifier."""
        return self.metadata.name

    @property
    def priority(self) -> int:
        """Routing priority (lower runs first)."""
        return self.metadata.priority

    @property
    def enabled(self) -> bool:
        """Whether this provider participates in routing."""
        return self.metadata.enabled

    def supports(self, entity_type: EntityType) -> bool:
        """True if this provider can report exposure for the given entity type."""
        return entity_type in self.metadata.supported_entity_types

    def has_capability(self, capability: ExposureCapability) -> bool:
        """True if this provider offers the given capability."""
        return capability in self.metadata.capabilities

    def provider_info(self) -> ExposureProviderMetadata:
        """Return this provider's metadata."""
        return self.metadata

    # --- finding construction helpers (shared by every provider) ---

    def _fail(
        self,
        entity: Entity,
        status: ExposureStatus,
        message: str,
        *,
        retryable: bool = False,
        detail: str | None = None,
    ) -> ExposureFinding:
        """Build a failed finding attributed to this provider."""
        info = self.metadata
        return ExposureFinding.failure(
            provider=info.name,
            provider_display_name=info.display_name,
            entity_type=entity.type,
            entity_value=entity.value,
            message=message,
            status=status,
            retryable=retryable,
            detail=detail,
        )

    def _not_found(self, entity_type: EntityType, entity_value: str) -> ExposureFinding:
        """Build a 'no data' finding attributed to this provider."""
        info = self.metadata
        return ExposureFinding.not_found(
            provider=info.name,
            provider_display_name=info.display_name,
            entity_type=entity_type,
            entity_value=entity_value,
        )

    def _unsupported(self, entity_type: EntityType, entity_value: str) -> ExposureFinding:
        """Build an 'unsupported entity type' finding attributed to this provider."""
        info = self.metadata
        return ExposureFinding.unsupported(
            provider=info.name,
            provider_display_name=info.display_name,
            entity_type=entity_type,
            entity_value=entity_value,
        )

    async def health(self) -> ExposureProviderHealth:
        """Report provider health.

        Phase 5.0 performs no network check: a disabled provider reports
        ``DISABLED``; otherwise ``UNKNOWN`` (a real probe arrives with each
        provider's implementation).
        """
        status = (
            ExposureProviderStatus.UNKNOWN
            if self.metadata.enabled
            else ExposureProviderStatus.DISABLED
        )
        return ExposureProviderHealth(name=self.name, status=status)

    async def safe_lookup(self, entity: Entity) -> ExposureFinding:
        """Run :meth:`lookup`, converting any unexpected exception into a finding.

        Providers are contracted never to raise, but this enforces the
        invariant at the framework boundary: a single buggy provider can never
        fail (or crash) a lookup. Orchestration calls this, not ``lookup``.
        """
        try:
            return await self.lookup(entity)
        except Exception as exc:
            return self._fail(
                entity,
                ExposureStatus.ERROR,
                "Provider raised an unexpected error",
                detail=str(exc),
            )

    # --- implemented by concrete providers in a later phase ---

    async def lookup(self, entity: Entity) -> ExposureFinding:
        """Look up ``entity``'s exposure and return a canonical finding (stub).

        Concrete providers fetch from their API and delegate to
        :meth:`normalize`; the return type is the contract every provider honors.
        """
        raise NotImplementedError(f"{self.name}.lookup is not implemented yet")

    async def normalize(self, raw: Any) -> ExposureFinding:
        """Map a raw provider payload into an :class:`ExposureFinding` (stub).

        Raw vendor JSON enters here and never leaves — only the canonical
        finding does.
        """
        raise NotImplementedError(f"{self.name}.normalize is not implemented yet")

    async def configuration(self) -> dict[str, Any]:
        """Report this provider's own configuration status (stub).

        e.g. whether an API key is present, the configured rate limit — never
        the credential value itself. Concrete providers implement this in a
        later phase; the framework never calls it on their behalf yet.
        """
        raise NotImplementedError(f"{self.name}.configuration is not implemented yet")
