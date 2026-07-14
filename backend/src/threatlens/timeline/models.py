"""Canonical models for the Investigation Timeline Framework (Phase 8.1).

A pure, deterministic, **read-only** consumer of a saved investigation's
already-computed :class:`~threatlens.reasoning.models.InvestigationSummary`.
It derives chronological events only from evidence that already carries an
explicit, timezone-aware timestamp — it never invents one, never estimates
chronology, and never infers causality between events. No AI, no
probabilistic inference, no new intelligence engine.

``event_type`` reuses :class:`~threatlens.providers.results.EvidenceType`
(the existing closed vocabulary describing *what kind* of observation a
piece of evidence is) rather than declaring a parallel enum — the timeline
never invents a category evidence didn't already carry.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from ..providers.results import EvidenceType
from ..reasoning.models import Severity

TIMELINE_FRAMEWORK_VERSION = "1.0"


class TimelineSourceType(StrEnum):
    """Which existing engine output a timeline event was derived from.

    Only ``INVESTIGATION_EVIDENCE`` is populated in Phase 8.1.
    ``DetectionPackage``/``DetectionArtifact`` and
    ``CorrelationSummary``/``CorrelationObservation`` carry no per-item
    evidence timestamp of their own — only a package/summary-level
    ``generated_at``, itself inherited from the source investigation and
    describing when that output was *computed*, never when an underlying
    security event was *observed*. Treating a processing timestamp as an
    event timestamp would be exactly the kind of invented chronology this
    framework refuses to produce, so this phase derives no events from
    either engine. See the architecture doc's "Known limitations".
    """

    INVESTIGATION_EVIDENCE = "investigation_evidence"


class TimelineEvent(BaseModel):
    """One chronological event, derived from a single piece of already-timestamped evidence.

    ``event_id`` is content-addressed (see ``engine.compute_event_id``): it
    hashes only stable evidence content — event type, subject, timestamp,
    summary, value — never a generation-time value, a random UUID, or list
    position, so the same underlying evidence always produces the same id.
    That same id is also the mechanism that collapses duplicate evidence
    (the same observation cited by more than one
    :class:`~threatlens.reasoning.models.Finding`) into one canonical event:
    ``source_id`` is the first (lexicographically smallest) finding id that
    cited it, and ``evidence_references`` is the full, sorted set of every
    finding id that did.

    ``severity`` is copied from the contributing finding(s) — the worst
    (highest) severity when more than one finding cites the same evidence —
    never recomputed.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=1)
    timestamp: datetime
    event_type: EvidenceType
    title: str = Field(min_length=1)
    description: str = ""
    source_type: TimelineSourceType
    source_id: str = Field(min_length=1)
    severity: Severity | None = None
    evidence_references: tuple[str, ...] = ()


class Timeline(BaseModel):
    """Every timeline event derived from one saved investigation, ordered deterministically.

    ``generated_at`` is inherited from the source
    ``InvestigationSummary.generated_at`` (or, when no summary is attached,
    the saved record's own ``updated_at``) — never the wall clock — so
    building a timeline twice from the same saved investigation yields a
    byte-identical ``Timeline``.
    """

    model_config = ConfigDict(frozen=True)

    investigation_id: UUID
    entity_type: EntityType
    entity_value: str
    generated_at: datetime
    events: tuple[TimelineEvent, ...] = ()

    @property
    def is_empty(self) -> bool:
        """True when no timestamped evidence produced an event."""
        return not self.events
