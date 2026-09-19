"""Identity lookup orchestration, caching, and local rate limiting."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import deque

from ..entities.models import Entity
from .cache import IdentityCache, InMemoryIdentityCache
from .config import IdentityConfig
from .models import IdentityFinding, IdentityStatus, IdentitySummary
from .registry import IdentityRegistry
from .summary import merge_findings

IDENTITY_FRAMEWORK_VERSION = "1.0.0"


class IdentityService:
    """Orchestrates concurrent identity-provider lookups for one entity."""

    def __init__(
        self,
        registry: IdentityRegistry,
        *,
        config: IdentityConfig | None = None,
        cache: IdentityCache[IdentityFinding] | None = None,
    ) -> None:
        self._registry = registry
        self._config = config or IdentityConfig(enabled=True)
        self._cache = cache or InMemoryIdentityCache()
        self._requests: deque[float] = deque()

    async def investigate(self, entity: Entity, *, refresh: bool = False) -> IdentitySummary:
        """Look up ``entity``'s identity data across every routed provider.

        Providers run concurrently via ``asyncio.gather``; a failed provider
        contributes its status, not an exception, and never blocks another.
        """
        summary, _ = await self.investigate_with_cache_state(entity, refresh=refresh)
        return summary

    async def investigate_with_cache_state(
        self, entity: Entity, *, refresh: bool = False
    ) -> tuple[IdentitySummary, bool]:
        """Investigate and report whether every routed result came from cache."""
        if not self._config.enabled:
            return merge_findings(
                (), entity_type=entity.type, entity_value=entity.value,
                framework_version=IDENTITY_FRAMEWORK_VERSION,
            ), False
        providers = self._registry.route(entity)
        results = await asyncio.gather(
            *(self._lookup(provider, entity, refresh=refresh) for provider in providers)
        )
        findings = [result[0] for result in results]
        summary = merge_findings(
            findings,
            entity_type=entity.type,
            entity_value=entity.value,
            framework_version=IDENTITY_FRAMEWORK_VERSION,
        )
        return summary, bool(results) and all(result[1] for result in results)

    async def _lookup(
        self, provider: object, entity: Entity, *, refresh: bool
    ) -> tuple[IdentityFinding, bool]:
        from .provider import IdentityProvider

        assert isinstance(provider, IdentityProvider)
        key_material = (
            f"{IDENTITY_FRAMEWORK_VERSION}|{provider.name}|{entity.type.value}|"
            f"{entity.normalized_value}|{self._config.cache_ttl_seconds}"
        )
        key = hashlib.sha256(key_material.encode()).hexdigest()
        if self._config.cache_enabled and not refresh:
            cached = self._cache.get(key)
            if cached is not None:
                return cached, True
        if not self._within_rate_limit():
            return provider._fail(
                entity, IdentityStatus.RATE_LIMITED,
                "Identity lookup rate limit reached", retryable=True,
            ), False
        finding = await provider.safe_lookup(entity)
        if self._config.cache_enabled and finding.status in {
            IdentityStatus.OK, IdentityStatus.NOT_FOUND,
        }:
            self._cache.set(key, finding, ttl_seconds=self._config.cache_ttl_seconds)
        return finding, False

    def _within_rate_limit(self) -> bool:
        limit = self._config.rate_limit_per_minute
        if limit is None:
            return True
        now = time.monotonic()
        while self._requests and now - self._requests[0] >= 60:
            self._requests.popleft()
        if len(self._requests) >= limit:
            return False
        self._requests.append(now)
        return True

    @property
    def config(self) -> IdentityConfig:
        return self._config

    @property
    def registry(self) -> IdentityRegistry:
        return self._registry
