"""Deterministic entity-to-provider routing.

Given a classified :class:`Entity`, returns the providers capable of enriching
it — decided entirely from declared metadata (supported entity types, declared
capabilities, enabled state), never from hardcoded provider names. Pure and
synchronous: routing makes no network calls.
"""

from __future__ import annotations

from ..entities.models import Entity
from ..entities.types import EntityType
from .base import IntelligenceProvider
from .registry import ProviderRegistry
from .types import ProviderCapability


class ProviderRouter:
    """Routes entities to capable providers using the registry."""

    def __init__(self, registry: ProviderRegistry) -> None:
        self._registry = registry

    def route(
        self,
        entity: Entity,
        *,
        capability: ProviderCapability | None = None,
    ) -> tuple[IntelligenceProvider, ...]:
        """Providers that can enrich ``entity``, in priority order.

        Keeps enabled providers whose ``supported_entity_types`` include the
        entity's type, optionally narrowed to those offering ``capability``.
        """
        return self.route_type(entity.type, capability=capability)

    def route_type(
        self,
        entity_type: EntityType,
        *,
        capability: ProviderCapability | None = None,
    ) -> tuple[IntelligenceProvider, ...]:
        """Same as :meth:`route` but keyed directly on an entity type."""
        return tuple(
            provider
            for provider in self._registry.providers  # already priority-ordered
            if provider.metadata.enabled
            and entity_type in provider.metadata.supported_entity_types
            and (capability is None or capability in provider.metadata.capabilities)
        )
