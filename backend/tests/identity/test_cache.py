"""Tests for InMemoryIdentityCache (the only concrete cache in Phase 6.0)."""

from __future__ import annotations

from threatlens.identity.cache import InMemoryIdentityCache


class _FakeClock:
    """A controllable clock so TTL expiry is deterministic, not time-based."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


class TestBasicOperations:
    def test_get_missing_key_returns_none(self) -> None:
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache()
        assert cache.get("missing") is None

    def test_set_then_get(self) -> None:
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache()
        cache.set("k", "v")
        assert cache.get("k") == "v"

    def test_invalidate_removes_key(self) -> None:
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache()
        cache.set("k", "v")
        cache.invalidate("k")
        assert cache.get("k") is None

    def test_invalidate_missing_key_is_a_no_op(self) -> None:
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache()
        cache.invalidate("missing")  # must not raise

    def test_clear_empties_the_cache(self) -> None:
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache()
        cache.set("a", "1")
        cache.set("b", "2")
        cache.clear()
        assert len(cache) == 0
        assert cache.get("a") is None


class TestTtlExpiry:
    def test_value_available_before_ttl_elapses(self) -> None:
        clock = _FakeClock(start=0.0)
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache(clock=clock)
        cache.set("k", "v", ttl_seconds=10)
        clock.now = 5.0
        assert cache.get("k") == "v"

    def test_value_expires_after_ttl_elapses(self) -> None:
        clock = _FakeClock(start=0.0)
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache(clock=clock)
        cache.set("k", "v", ttl_seconds=10)
        clock.now = 10.0
        assert cache.get("k") is None

    def test_no_ttl_never_expires(self) -> None:
        clock = _FakeClock(start=0.0)
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache(clock=clock)
        cache.set("k", "v")
        clock.now = 10_000.0
        assert cache.get("k") == "v"

    def test_expired_entry_is_evicted_on_read(self) -> None:
        clock = _FakeClock(start=0.0)
        cache: InMemoryIdentityCache[str] = InMemoryIdentityCache(clock=clock)
        cache.set("k", "v", ttl_seconds=1)
        clock.now = 2.0
        cache.get("k")
        assert len(cache) == 0
