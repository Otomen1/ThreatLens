"""Investigation Timeline Framework (Phase 8.1).

A pure, deterministic, **read-only** consumer of a saved investigation's
existing outputs — not a new intelligence engine. It derives chronological
:class:`TimelineEvent` objects only from evidence that already carries an
explicit, timezone-aware timestamp
(:class:`~threatlens.reasoning.models.Finding` → ``evidence`` →
:class:`~threatlens.providers.results.Evidence.observed_at`). It never
invents a timestamp, estimates chronology, or infers causality; evidence
with no valid timestamp is silently omitted, never backfilled with the
current time. No AI, no probabilistic inference.

Consumes a :class:`~threatlens.workspace.models.WorkspaceInvestigation` via
:class:`TimelineService`; never mutates it, never persists timeline data of
its own (Phase 8.1 always derives, never duplicates-and-stores).
"""

from __future__ import annotations

from .engine import (
    TIMELINE_ENGINE_VERSION,
    collect_events,
    compute_event_id,
    is_valid_evidence_timestamp,
    sort_events,
)
from .models import (
    TIMELINE_FRAMEWORK_VERSION,
    Timeline,
    TimelineEvent,
    TimelineSourceType,
)
from .service import TimelineService

__all__ = [
    "TIMELINE_ENGINE_VERSION",
    "TIMELINE_FRAMEWORK_VERSION",
    "Timeline",
    "TimelineEvent",
    "TimelineService",
    "TimelineSourceType",
    "collect_events",
    "compute_event_id",
    "is_valid_evidence_timestamp",
    "sort_events",
]
