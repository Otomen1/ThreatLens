"""The exposure-provider registry.

A small explicit container — the extension seam for adding exposure
providers — mirroring ``providers/registry.py``. It also owns deterministic
entity-to-provider routing (folded in here rather than a separate router
module, per Phase 5.0's leaner file layout): given a classified entity,
returns the providers capable of reporting exposure for it, decided entirely
from declared metadata, never hardcoded names. Routing is pure and
synchronous — it makes no network calls itself (a routed provider's own
``lookup`` is the only network-touching step). No global mutable state, so
tests build isolated registries.
"""

from __future__ import annotations

from ..entities.models import Entity
from ..entities.types import EntityType
from .exceptions import DuplicateExposureProviderError
from .models import ExposureCapability
from .provider import ExposureProvider
from .providers.censys import CensysProvider
from .providers.shodan import ShodanProvider


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

    Phase 5.1 registered the first concrete provider, :class:`ShodanProvider`.
    Phase 5.2 adds the second, :class:`CensysProvider`, through the exact same
    integration point Phase 5.0 reserved (this function, unmodified in
    shape) — proving the registry, routing, and aggregation already scale to
    more than one provider with no framework change. Both are always
    registered; whether each participates in routing is controlled by its
    own ``*_ENABLED`` setting via ``ExposureProviderMetadata.enabled``, the
    same mechanism :meth:`ExposureRegistry.route` already filters on. With
    equal default priority, ordering falls back to the existing
    priority-then-name tiebreak, so ``censys`` sorts before ``shodan`` —
    deterministic without any new ordering logic.
    """
    registry = ExposureRegistry()
    registry.register(CensysProvider())
    registry.register(ShodanProvider())
    return registry
