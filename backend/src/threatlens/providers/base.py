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

    # --- implemented by concrete providers in later phases ---

    async def search(self, entity: Entity) -> Any:
        """Query the provider for intelligence about ``entity`` (stub)."""
        raise NotImplementedError(f"{self.name}.search is not implemented yet")

    async def normalize(self, raw: Any) -> Any:
        """Map a raw provider payload into the common result shape (stub)."""
        raise NotImplementedError(f"{self.name}.normalize is not implemented yet")
