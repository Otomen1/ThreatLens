"""Unified investigation service — concurrent TI + Reference execution.

Runs intelligence providers and reference providers in a single asyncio.gather,
splits the results by framework, and aggregates each group independently. This
gives callers one aggregated view of TI data and one of reference knowledge
without coupling the two frameworks or requiring sequential execution.
"""

from __future__ import annotations

import asyncio

from ..entities.models import Entity
from ..providers import AggregatedResult, ProviderRouter, aggregate
from ..reference import ReferenceRouter


class InvestigationService:
    """Orchestrates concurrent TI + Reference lookup for one entity."""

    def __init__(self, ti_router: ProviderRouter, ref_router: ReferenceRouter) -> None:
        self._ti_router = ti_router
        self._ref_router = ref_router

    async def investigate(self, entity: Entity) -> tuple[AggregatedResult, AggregatedResult]:
        """Run all routed providers concurrently; return (threat_intelligence, knowledge).

        Providers from both frameworks run in a single asyncio.gather — never
        sequentially. Each framework's results are aggregated independently. A
        failed provider contributes its status but not its findings; it never
        blocks the other framework or the other providers within the same framework.
        """
        ti_providers = self._ti_router.route(entity)
        ref_providers = self._ref_router.route(entity)

        ti_coros = [p.safe_search(entity) for p in ti_providers]
        ref_coros = [p.safe_lookup(entity) for p in ref_providers]

        all_results = await asyncio.gather(*ti_coros, *ref_coros)

        ti_count = len(ti_coros)
        ti_results = all_results[:ti_count]
        ref_results = all_results[ti_count:]

        ti_aggregated = aggregate(ti_results, entity_type=entity.type, entity_value=entity.value)
        ref_aggregated = aggregate(ref_results, entity_type=entity.type, entity_value=entity.value)
        return ti_aggregated, ref_aggregated
