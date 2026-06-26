"""Deterministic entity-to-reference-provider routing.

Given a classified :class:`Entity`, returns the reference providers that hold
knowledge for it — decided entirely from declared metadata (supported entity
types, capabilities, enabled state), never hardcoded names. Adding a future
provider (MITRE, NVD, CWE, CAPEC) requires no change here. Pure and synchronous.
"""

from __future__ import annotations

from ..entities.models import Entity
from ..entities.types import EntityType
from .base import ReferenceProvider
from .registry import ReferenceRegistry
from .types import ReferenceCapability


class ReferenceRouter:
    """Routes entities to reference providers using the registry."""

    def __init__(self, registry: ReferenceRegistry) -> None:
        self._registry = registry

    def route(
        self,
        entity: Entity,
        *,
        capability: ReferenceCapability | None = None,
    ) -> tuple[ReferenceProvider, ...]:
        """Reference providers with knowledge for ``entity``, in priority order."""
        return self.route_type(entity.type, capability=capability)

    def route_type(
        self,
        entity_type: EntityType,
        *,
        capability: ReferenceCapability | None = None,
    ) -> tuple[ReferenceProvider, ...]:
        """Same as :meth:`route` but keyed directly on an entity type."""
        return tuple(
            provider
            for provider in self._registry.providers  # already priority-ordered
            if provider.metadata.enabled
            and entity_type in provider.metadata.supported_entity_types
            and (capability is None or capability in provider.metadata.capabilities)
        )
