"""The intelligence-provider interface.

Mirrors the detector ABC in ``search/detectors/base.py``: a provider declares
static :class:`ProviderMetadata` and the framework handles registration and
routing. The only abstract member is ``metadata`` — that is all a provider needs
to be registered and routed. The network-touching methods (``search``,
``normalize``, ``health``) are async to match the Phase 0 source contract and are
stubbed here; concrete providers implement them in later phases (1.3+).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..entities.models import Entity
from ..entities.types import EntityType
from .models import ProviderHealth, ProviderMetadata
from .results import IntelligenceResult, ResultStatus
from .types import ProviderCapability, ProviderStatus


class IntelligenceProvider(ABC):
    """Base class for all intelligence providers."""

    @property
    @abstractmethod
    def metadata(self) -> ProviderMetadata:
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
        """True if this provider can enrich the given entity type."""
        return entity_type in self.metadata.supported_entity_types

    def has_capability(self, capability: ProviderCapability) -> bool:
        """True if this provider offers the given capability."""
        return capability in self.metadata.capabilities

    def provider_info(self) -> ProviderMetadata:
        """Return this provider's metadata."""
        return self.metadata

    # --- result construction helpers (shared by every provider) ---

    def _fail(
        self,
        entity: Entity,
        status: ResultStatus,
        message: str,
        *,
        retryable: bool = False,
        detail: str | None = None,
    ) -> IntelligenceResult:
        """Build a failed result attributed to this provider."""
        info = self.metadata
        return IntelligenceResult.failure(
            provider=info.name,
            provider_display_name=info.display_name,
            entity_type=entity.type,
            entity_value=entity.value,
            message=message,
            status=status,
            retryable=retryable,
            detail=detail,
        )

    def _not_found(self, entity_type: EntityType, entity_value: str) -> IntelligenceResult:
        """Build a 'no data' result attributed to this provider."""
        info = self.metadata
        return IntelligenceResult.not_found(
            provider=info.name,
            provider_display_name=info.display_name,
            entity_type=entity_type,
            entity_value=entity_value,
        )

    def _unsupported(self, entity_type: EntityType, entity_value: str) -> IntelligenceResult:
        """Build an 'unsupported entity type' result attributed to this provider."""
        info = self.metadata
        return IntelligenceResult.unsupported(
            provider=info.name,
            provider_display_name=info.display_name,
            entity_type=entity_type,
            entity_value=entity_value,
        )

    async def health(self) -> ProviderHealth:
        """Report provider health.

        Phase 1.2 performs no network check: a disabled provider reports
        ``DISABLED``; otherwise ``UNKNOWN`` (a real probe arrives with each
        provider's implementation).
        """
        status = (
            ProviderStatus.UNKNOWN if self.metadata.enabled else ProviderStatus.DISABLED
        )
        return ProviderHealth(name=self.name, status=status)

    async def safe_search(self, entity: Entity) -> IntelligenceResult:
        """Run :meth:`search`, converting any unexpected exception into a result.

        Providers are contracted never to raise, but this enforces the invariant
        at the framework boundary: a single buggy provider can never fail (or
        crash) a search. Orchestration should call this, not ``search`` directly.
        """
        try:
            return await self.search(entity)
        except Exception as exc:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "Provider raised an unexpected error",
                detail=str(exc),
            )

    # --- implemented by concrete providers in later phases ---

    async def search(self, entity: Entity) -> IntelligenceResult:
        """Look up ``entity`` and return a canonical result (stub).

        Concrete providers fetch from their API and delegate to
        :meth:`normalize`; the return type is the contract every provider honors.
        """
        raise NotImplementedError(f"{self.name}.search is not implemented yet")

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map a raw provider payload into an :class:`IntelligenceResult` (stub).

        This is the normalization contract: raw vendor JSON enters here and never
        leaves — only the canonical result does.
        """
        raise NotImplementedError(f"{self.name}.normalize is not implemented yet")
