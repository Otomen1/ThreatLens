"""The community detection provider interface + registry (Phase 4.6).

A provider is a **read-only** adapter over one community repository. It declares
its repository metadata, yields raw records (fetched offline from the local cache
/ bundled seed, or — via a future subclass — synced from upstream), and
normalizes them into canonical :class:`CommunityRule`s. A provider can *only*
produce community rules; it has no access to and never mutates ThreatLens's
generated detections.

The registry is a parallel to ``reference.ReferenceRegistry`` — kept separate so
the frameworks stay independent — holding providers in deterministic priority
order with no global mutable state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from ..models import CommunityRule, RuleReference, RuleSource
from ..normalize import normalize_record


class CommunityProvider(ABC):
    """Base class for all community detection providers (read-only)."""

    @property
    @abstractmethod
    def metadata(self) -> RuleSource:
        """Static description of the repository this provider federates over."""

    @abstractmethod
    def iter_records(self) -> Iterable[dict[str, object]]:
        """Yield raw upstream records (offline: from cache / bundled seed).

        A record is a plain dict carrying at least ``rule_id`` and ``content``;
        it is never fetched during an investigation (see ``sync``).
        """

    # --- convenience accessors derived from metadata ---

    @property
    def name(self) -> str:
        return self.metadata.id

    @property
    def priority(self) -> int:
        return self.metadata.priority

    # --- concrete framework behaviour (providers rarely override) ---

    def normalize(self, record: dict[str, object]) -> CommunityRule:
        """Map one raw record into a canonical rule (delegates to the pipeline)."""
        return normalize_record(self.metadata, record)

    def rules(self) -> tuple[CommunityRule, ...]:
        """All of this provider's records, normalized (deterministic order)."""
        normalized = [self.normalize(record) for record in self.iter_records()]
        normalized.sort(key=lambda rule: rule.id)
        return tuple(normalized)

    def references(self) -> tuple[RuleReference, ...]:
        """Provider-level references (the repository itself)."""
        source = self.metadata
        return (RuleReference(title=source.name, url=source.url),)


class DuplicateCommunityProviderError(ValueError):
    """Raised when registering a provider whose id already exists."""

    def __init__(self, name: str) -> None:
        super().__init__(f"a community provider named {name!r} is already registered")
        self.name = name


class CommunityProviderRegistry:
    """Holds community providers keyed by unique id, ordered by priority."""

    def __init__(self) -> None:
        self._providers: dict[str, CommunityProvider] = {}
        self._sorted: tuple[CommunityProvider, ...] | None = None

    def register(self, provider: CommunityProvider) -> None:
        """Add a provider; raise on id clash."""
        name = provider.metadata.id
        if name in self._providers:
            raise DuplicateCommunityProviderError(name)
        self._providers[name] = provider
        self._sorted = None

    def get(self, name: str) -> CommunityProvider | None:
        return self._providers.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._providers

    def __len__(self) -> int:
        return len(self._providers)

    @property
    def providers(self) -> tuple[CommunityProvider, ...]:
        """All providers, ordered by ascending priority then id."""
        if self._sorted is None:
            self._sorted = tuple(
                sorted(self._providers.values(), key=lambda p: (p.priority, p.name))
            )
        return self._sorted

    def all_rules(self) -> tuple[CommunityRule, ...]:
        """Normalized rules from every provider, in deterministic order."""
        rules = [rule for provider in self.providers for rule in provider.rules()]
        rules.sort(key=lambda rule: (rule.source.priority, rule.source.id, rule.id))
        return tuple(rules)
