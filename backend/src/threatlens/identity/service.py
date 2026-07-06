"""The Identity Intelligence service — entity in, ``IdentitySummary`` out.

Mirrors ``exposure/service.py`` / ``investigation/service.py``: fans out to
every provider the registry routes to and merges the results. With zero
providers registered (Phase 6.0), ``route()`` always returns an empty tuple,
so ``investigate`` naturally returns a well-formed, empty summary through the
*real* code path — not a special-cased stub. A later phase's providers plug
into this unmodified.
"""

from __future__ import annotations

import asyncio

from ..entities.models import Entity
from .models import IdentitySummary
from .registry import IdentityRegistry
from .summary import merge_findings

IDENTITY_FRAMEWORK_VERSION = "0.1.0"
"""Pre-1.0: the framework is complete but carries no providers yet (Phase
6.0). Moves to "1.0" once real providers ship and are validated end-to-end —
the same "frozen after validation" convention as the Reasoning, Detection, and
Exposure Engines."""


class IdentityService:
    """Orchestrates concurrent identity-provider lookups for one entity."""

    def __init__(self, registry: IdentityRegistry) -> None:
        self._registry = registry

    async def investigate(self, entity: Entity) -> IdentitySummary:
        """Look up ``entity``'s identity data across every routed provider.

        Providers run concurrently via ``asyncio.gather``; a failed provider
        contributes its status, not an exception, and never blocks another.
        """
        providers = self._registry.route(entity)
        findings = await asyncio.gather(*(p.safe_lookup(entity) for p in providers))
        return merge_findings(
            findings,
            entity_type=entity.type,
            entity_value=entity.value,
            framework_version=IDENTITY_FRAMEWORK_VERSION,
        )
