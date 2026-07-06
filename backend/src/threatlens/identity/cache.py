"""Cache abstractions for the Identity Intelligence Framework (interfaces only).

No persistence implementation, no Redis, no database — just the interface a
future provider or service layer caches lookups against, plus an in-memory
default. Concrete persistent backends are a later phase's concern; nothing
here is wired into ``IdentityService`` yet.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Generic, TypeVar

_T = TypeVar("_T")


class IdentityCache(ABC, Generic[_T]):
    """A read/write cache keyed by opaque string keys.

    Callers choose the key shape (e.g. ``f"{provider}:{entity_type}:{value}"``).
    ``ttl_seconds=None`` means "no expiry."
    """

    @abstractmethod
    def get(self, key: str) -> _T | None:
        """Return the cached value for ``key``, or ``None`` if absent/expired."""

    @abstractmethod
    def set(self, key: str, value: _T, *, ttl_seconds: float | None = None) -> None:
        """Store ``value`` under ``key``, expiring after ``ttl_seconds`` (if given)."""

    @abstractmethod
    def invalidate(self, key: str) -> None:
        """Remove ``key`` from the cache, if present."""

    @abstractmethod
    def clear(self) -> None:
        """Remove every entry from the cache."""


class InMemoryIdentityCache(IdentityCache[_T]):
    """A process-local, in-memory default — no persistence across restarts."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._store: dict[str, tuple[_T, float | None]] = {}
        self._clock = clock

    def get(self, key: str) -> _T | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and self._clock() >= expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: _T, *, ttl_seconds: float | None = None) -> None:
        expires_at = self._clock() + ttl_seconds if ttl_seconds is not None else None
        self._store[key] = (value, expires_at)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
