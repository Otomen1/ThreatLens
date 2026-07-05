"""The exposure-provider registry.

A small explicit container — the extension seam for adding exposure
providers — mirroring ``providers/registry.py``. It also owns deterministic
entity-to-provider routing (folded in here rather than a separate router
module, since Phase 5.0 has no providers to route to yet): given a
classified entity, returns the providers capable of reporting exposure for
it, decided entirely from declared metadata, never hardcoded names. Routing
is pure and synchronous — it makes no network calls. No global mutable
state, so tests build isolated registries.
"""

from __future__ import annotations

from ..entities.models import Entity
from ..entities.types import EntityType
from .exceptions import DuplicateExposureProviderError
from .models import ExposureCapability
from .provider import ExposureProvider


class ExposureRegistry:
    """Holds exposure providers keyed by unique name, ordered by priority."""

    def __init__(self) -> None:
        self._providers: dict[str, ExposureProvider] = {}

    def register(self, provider: ExposureProvider) -> None:
        """Add a provider; raise :class:`DuplicateExposureProviderError` on name clash."""
        name = provider.metadata.name
        if name in self._providers:
            raise DuplicateExposureProviderError(name)
        self._providers[name] = provider

    def get(self, name: str) -> ExposureProvider | None:
        """Return the registered provider with ``name``, or ``None``."""
        return self._providers.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    @property
    def providers(self) -> tuple[ExposureProvider, ...]:
        """All registered providers, ordered by ascending priority then name."""
        return tuple(
            sorted(
                self._providers.values(),
                key=lambda p: (p.metadata.priority, p.metadata.name),
            )
        )

    def route(
        self,
        entity: Entity,
        *,
        capability: ExposureCapability | None = None,
    ) -> tuple[ExposureProvider, ...]:
        """Providers that can report exposure for ``entity``, in priority order.

        Keeps enabled providers whose ``supported_entity_types`` include the
        entity's type, optionally narrowed to those offering ``capability``.
        """
        return self.route_type(entity.type, capability=capability)

    def route_type(
        self,
        entity_type: EntityType,
        *,
        capability: ExposureCapability | None = None,
    ) -> tuple[ExposureProvider, ...]:
        """Same as :meth:`route` but keyed directly on an entity type."""
        return tuple(
            provider
            for provider in self.providers  # already priority-ordered
            if provider.metadata.enabled
            and entity_type in provider.metadata.supported_entity_types
            and (capability is None or capability in provider.metadata.capabilities)
        )


def build_default_registry() -> ExposureRegistry:
    """Build the default exposure-provider registry.

    Phase 5.0 registers no providers — the framework, routing, and service
    all work correctly over an empty registry, exercising the real code path
    future providers will use unmodified.
    """
    return ExposureRegistry()
