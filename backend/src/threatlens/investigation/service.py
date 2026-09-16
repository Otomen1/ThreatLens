"""Unified investigation service — concurrent TI + Reference execution.

Runs intelligence providers and reference providers in a single asyncio.gather,
splits the results by framework, and aggregates each group independently. This
gives callers one aggregated view of TI data and one of reference knowledge
without coupling the two frameworks or requiring sequential execution.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from ..entities.models import Entity
from ..providers import AggregatedResult, ProviderRouter, aggregate
from ..reference import ReferenceRouter


class InvestigationService:
    """Orchestrates concurrent TI + Reference lookup for one entity."""

    def __init__(
        self,
        ti_router: ProviderRouter,
        ref_router: ReferenceRouter,
        *,
        max_concurrency: int | None = None,
    ) -> None:
        self._ti_router = ti_router
        self._ref_router = ref_router
        configured = max_concurrency or int(os.getenv("THREATLENS_PROVIDER_CONCURRENCY", "8"))
        self._semaphore = asyncio.Semaphore(max(1, configured))

    async def _lookup(self, provider: Any, entity: Entity, *, reference: bool) -> Any:
        from ..system.telemetry import enter_provider, leave_provider

        async with self._semaphore:
            token = enter_provider(provider.name)
            try:
                return await (
                    provider.safe_lookup(entity) if reference else provider.safe_search(entity)
                )
            finally:
                leave_provider(token)

    def routed_provider_names(
        self,
        entity: Entity,
        *,
        scan_mode: str = "standard",
        excluded_providers: frozenset[str] = frozenset(),
    ) -> list[str]:
        return [
            provider.name
            for provider in self._ti_providers(
                entity, scan_mode=scan_mode, excluded_providers=excluded_providers
            )
        ]

    def _ti_providers(
        self,
        entity: Entity,
        *,
        scan_mode: str,
        excluded_providers: frozenset[str],
    ) -> tuple[Any, ...]:
        providers = tuple(
            provider
            for provider in self._ti_router.route(entity)
            if provider.name not in excluded_providers
        )
        return providers[:1] if scan_mode == "fast" else providers

    async def investigate(
        self,
        entity: Entity,
        *,
        scan_mode: str = "standard",
        excluded_providers: frozenset[str] = frozenset(),
    ) -> tuple[AggregatedResult, AggregatedResult]:
        """Run all routed providers concurrently; return (threat_intelligence, knowledge).

        Providers from both frameworks run in a single asyncio.gather — never
        sequentially. Each framework's results are aggregated independently. A
        failed provider contributes its status but not its findings; it never
        blocks the other framework or the other providers within the same framework.
        """
        ti_providers = self._ti_providers(
            entity, scan_mode=scan_mode, excluded_providers=excluded_providers
        )
        ref_providers = self._ref_router.route(entity)

        ti_coros = [self._lookup(p, entity, reference=False) for p in ti_providers]
        ref_coros = [self._lookup(p, entity, reference=True) for p in ref_providers]

        all_results = await asyncio.gather(*ti_coros, *ref_coros)

        ti_count = len(ti_coros)
        ti_results = all_results[:ti_count]
        ref_results = all_results[ti_count:]

        ti_aggregated = aggregate(ti_results, entity_type=entity.type, entity_value=entity.value)
        ref_aggregated = aggregate(ref_results, entity_type=entity.type, entity_value=entity.value)
        return ti_aggregated, ref_aggregated

    def estimate_ti_requests(
        self,
        entity: Entity,
        *,
        scan_mode: str = "standard",
        excluded_providers: frozenset[str] = frozenset(),
    ) -> int:
        """Return routed TI-provider count without making network requests."""
        return len(
            self._ti_providers(entity, scan_mode=scan_mode, excluded_providers=excluded_providers)
        )
