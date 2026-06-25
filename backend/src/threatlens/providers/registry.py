"""The intelligence-provider registry.

Like ``search/registry.py``, a small explicit container — the extension seam for
adding providers. It enforces unique provider names and exposes providers in a
deterministic priority order. No global mutable state, so tests build isolated
registries.
"""

from __future__ import annotations

from .base import IntelligenceProvider


class DuplicateProviderError(ValueError):
    """Raised when registering a provider whose name is already registered."""

    def __init__(self, name: str) -> None:
        super().__init__(f"a provider named {name!r} is already registered")
        self.name = name


class ProviderRegistry:
    """Holds intelligence providers keyed by unique name, ordered by priority."""

    def __init__(self) -> None:
        self._providers: dict[str, IntelligenceProvider] = {}

    def register(self, provider: IntelligenceProvider) -> None:
        """Add a provider; raise :class:`DuplicateProviderError` on name clash."""
        name = provider.metadata.name
        if name in self._providers:
            raise DuplicateProviderError(name)
        self._providers[name] = provider

    def get(self, name: str) -> IntelligenceProvider | None:
        """Return the registered provider with ``name``, or ``None``."""
        return self._providers.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    @property
    def providers(self) -> tuple[IntelligenceProvider, ...]:
        """All registered providers, ordered by ascending priority then name."""
        return tuple(
            sorted(
                self._providers.values(),
                key=lambda p: (p.metadata.priority, p.metadata.name),
            )
        )
