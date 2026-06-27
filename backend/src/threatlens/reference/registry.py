"""The reference-knowledge provider registry.

A parallel to ``providers.ProviderRegistry`` (kept separate so the two
frameworks stay independent). Holds reference providers keyed by unique name and
exposes them in deterministic priority order. No global mutable state, so tests
build isolated registries.
"""

from __future__ import annotations

from .base import ReferenceProvider


class DuplicateReferenceProviderError(ValueError):
    """Raised when registering a reference provider whose name already exists."""

    def __init__(self, name: str) -> None:
        super().__init__(f"a reference provider named {name!r} is already registered")
        self.name = name


class ReferenceRegistry:
    """Holds reference providers keyed by unique name, ordered by priority."""

    def __init__(self) -> None:
        self._providers: dict[str, ReferenceProvider] = {}
        self._sorted: tuple[ReferenceProvider, ...] | None = None

    def register(self, provider: ReferenceProvider) -> None:
        """Add a provider; raise on name clash."""
        name = provider.metadata.name
        if name in self._providers:
            raise DuplicateReferenceProviderError(name)
        self._providers[name] = provider
        self._sorted = None  # invalidate cached order

    def get(self, name: str) -> ReferenceProvider | None:
        """Return the registered provider with ``name``, or ``None``."""
        return self._providers.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    @property
    def providers(self) -> tuple[ReferenceProvider, ...]:
        """All registered providers, ordered by ascending priority then name."""
        if self._sorted is None:
            self._sorted = tuple(
                sorted(
                    self._providers.values(),
                    key=lambda p: (p.metadata.priority, p.metadata.name),
                )
            )
        return self._sorted
