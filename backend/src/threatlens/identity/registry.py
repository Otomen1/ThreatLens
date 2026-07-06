"""The identity-provider registry.

A small explicit container — the extension seam for adding identity
providers — mirroring ``exposure/registry.py``. It also owns deterministic
entity-to-provider routing (folded in here rather than a separate router
module, per the sibling frameworks' leaner file layout): given a classified
entity, returns the providers capable of reporting identity data for it,
decided entirely from declared metadata, never hardcoded names. Routing is
pure and synchronous — it makes no network calls itself (a routed provider's
own ``lookup`` is the only network-touching step). No global mutable state, so
tests build isolated registries.
"""

from __future__ import annotations

from ..entities.models import Entity
from ..entities.types import EntityType
from .exceptions import DuplicateIdentityProviderError
from .models import IdentityCapability
from .provider import IdentityProvider


class IdentityRegistry:
    """Holds identity providers keyed by unique name, ordered by priority."""

    def __init__(self) -> None:
        self._providers: dict[str, IdentityProvider] = {}

    def register(self, provider: IdentityProvider) -> None:
        """Add a provider; raise :class:`DuplicateIdentityProviderError` on name clash."""
        name = provider.metadata.name
        if name in self._providers:
            raise DuplicateIdentityProviderError(name)
        self._providers[name] = provider

    def get(self, name: str) -> IdentityProvider | None:
        """Return the registered provider with ``name``, or ``None``."""
        return self._providers.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    @property
    def providers(self) -> tuple[IdentityProvider, ...]:
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
        capability: IdentityCapability | None = None,
    ) -> tuple[IdentityProvider, ...]:
        """Providers that can report identity data for ``entity``, in priority order.

        Keeps enabled providers whose ``supported_entity_types`` include the
        entity's type, optionally narrowed to those offering ``capability``.
        """
        return self.route_type(entity.type, capability=capability)

    def route_type(
        self,
        entity_type: EntityType,
        *,
        capability: IdentityCapability | None = None,
    ) -> tuple[IdentityProvider, ...]:
        """Same as :meth:`route` but keyed directly on an entity type."""
        return tuple(
            provider
            for provider in self.providers  # already priority-ordered
            if provider.metadata.enabled
            and entity_type in provider.metadata.supported_entity_types
            and (capability is None or capability in provider.metadata.capabilities)
        )


def build_default_registry() -> IdentityRegistry:
    """Build the default identity-provider registry.

    Phase 6.0 ships **zero** concrete providers, so this returns an empty
    registry — the routing, aggregation, and service paths are all real and
    tested against it. A Phase 6.1+ provider (HIBP, Entra ID, Okta, …)
    registers here exactly as ``exposure.registry.build_default_registry``
    registers Shodan/Censys/GreyNoise, without changing this function's shape.
    """
    return IdentityRegistry()
