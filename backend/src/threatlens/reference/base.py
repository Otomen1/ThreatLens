"""The reference-knowledge provider interface.

A parallel to ``providers.IntelligenceProvider`` for static, versioned knowledge
sources (MITRE ATT&CK, NVD, CWE, CAPEC, …). A reference provider retrieves and
normalizes structured knowledge into the *shared* canonical
:class:`IntelligenceResult` — populating references, relationships, evidence, and
metadata, but NEVER reputation, scoring, or confidence (those are TI concerns).

Reusing the canonical result is deliberate: a future "ThreatLens Intelligence
Document" combines TI results and reference results through the existing
``providers.aggregate`` with no new aggregation logic.

The only abstract member is ``metadata``; ``lookup``/``normalize`` are stubs
implemented by concrete providers in later phases (MITRE first).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..entities.models import Entity
from ..entities.types import EntityType
from ..providers.results import IntelligenceResult, ResultStatus
from .models import ReferenceMetadata
from .types import ReferenceCapability


class ReferenceProvider(ABC):
    """Base class for all reference knowledge providers."""

    @property
    @abstractmethod
    def metadata(self) -> ReferenceMetadata:
        """Static description of this provider and its dataset."""

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
        """True if this provider has knowledge for the given entity type."""
        return entity_type in self.metadata.supported_entity_types

    def has_capability(self, capability: ReferenceCapability) -> bool:
        """True if this provider exposes the given kind of knowledge."""
        return capability in self.metadata.capabilities

    def provider_info(self) -> ReferenceMetadata:
        """Return this provider's metadata."""
        return self.metadata

    async def safe_lookup(self, entity: Entity) -> IntelligenceResult:
        """Run :meth:`lookup`, converting any unexpected exception into a result.

        Enforces the "never crash a search" invariant at the framework boundary,
        mirroring ``IntelligenceProvider.safe_search``.
        """
        try:
            return await self.lookup(entity)
        except Exception as exc:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "Reference provider raised an unexpected error",
                detail=str(exc),
            )

    # --- implemented by concrete providers in later phases ---

    async def lookup(self, entity: Entity) -> IntelligenceResult:
        """Retrieve structured knowledge about ``entity`` (stub).

        Returns a canonical result with references/relationships/evidence and no
        reputation. Concrete providers delegate to :meth:`normalize`.
        """
        raise NotImplementedError(f"{self.name}.lookup is not implemented yet")

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map a raw knowledge record into an :class:`IntelligenceResult` (stub)."""
        raise NotImplementedError(f"{self.name}.normalize is not implemented yet")

    # --- result construction helpers (reference results carry no reputation) ---

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
        """Build a 'no knowledge' result attributed to this provider."""
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
