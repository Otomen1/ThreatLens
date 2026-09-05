"""The Exposure Intelligence service — entity in, ``ExposureSummary`` out.

Mirrors ``investigation/service.py``: fans out to every provider the
registry routes to and merges the results. With zero providers registered
(Phase 5.0), ``route()`` always returns an empty tuple, so ``investigate``
naturally returns a well-formed, empty summary through the *real* code path —
not a special-cased stub. A later phase's providers plug into this
unmodified.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from ..entities.models import Entity
from .models import ExposureSummary
from .registry import ExposureRegistry
from .summary import merge_findings

EXPOSURE_FRAMEWORK_VERSION = "1.0"
"""Frozen at 1.0 (Phase 5.4): three independent providers (Shodan, Censys,
GreyNoise) validated end-to-end against a 153-scenario corpus with zero
invariant violations — the same "frozen after validation" convention as the
Reasoning and Detection Engines. See
``docs/architecture/PHASE-5.4-EXPOSURE-ENGINE-V1.md``. Future provider
additions are additive only; a change to merge/routing/statistics semantics
must regenerate ``tests/exposure_validation/golden.json`` and bump this
version."""


class ExposureService:
    """Orchestrates concurrent exposure-provider lookups for one entity."""

    def __init__(self, registry: ExposureRegistry, *, max_concurrency: int | None = None) -> None:
        self._registry = registry
        configured = max_concurrency or int(os.getenv("THREATLENS_PROVIDER_CONCURRENCY", "8"))
        self._semaphore = asyncio.Semaphore(max(1, configured))

    async def investigate(self, entity: Entity) -> ExposureSummary:
        """Look up ``entity``'s exposure across every routed provider.

        Providers run concurrently via ``asyncio.gather``; a failed provider
        contributes its status, not an exception, and never blocks another.
        """
        providers = self._registry.route(entity)

        async def lookup(provider: Any) -> Any:
            async with self._semaphore:
                return await provider.safe_lookup(entity)

        findings = await asyncio.gather(*(lookup(p) for p in providers))
        return merge_findings(
            findings,
            entity_type=entity.type,
            entity_value=entity.value,
            framework_version=EXPOSURE_FRAMEWORK_VERSION,
        )
