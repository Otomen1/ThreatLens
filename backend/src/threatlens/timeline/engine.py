"""The Investigation Timeline Engine (Phase 8.1).

Pure, deterministic, offline. The only function that touches the wall clock
anywhere in this module is nowhere — every value in a :class:`~threatlens.timeline.models.Timeline`
is derived from its input, never from ``datetime.now()``.

The single evidence source in this phase: :class:`~threatlens.reasoning.models.Finding`
`.evidence[].evidence.evidence` — a :class:`~threatlens.providers.results.Evidence`
record, reached through ``WeightedEvidence`` → ``AttributedEvidence`` — when
its ``observed_at`` is a valid, timezone-aware datetime. Detection and
Correlation outputs carry no such per-item timestamp (see
``models.TimelineSourceType`` and the architecture doc), so this phase
derives no events from them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime

from ..providers.results import Evidence
from ..reasoning.models import Finding, InvestigationSummary, Severity
from .models import TimelineEvent, TimelineSourceType

TIMELINE_ENGINE_VERSION = "1.0"


def is_valid_evidence_timestamp(value: datetime | None) -> bool:
    """Whether ``value`` is usable as a timeline event's timestamp.

    Two things make a timestamp invalid for this framework's purposes: it is
    simply absent (``None`` — the provider never reported a time), or it is
    timezone-naive. A naive datetime cannot be deterministically compared
    against the timezone-aware datetimes the rest of the codebase uses
    (`reason(..., now=...)`'s own convention) without *assuming* a timezone
    it doesn't actually carry — and assuming one would be exactly the kind
    of invented chronology this framework refuses to produce. Naive
    timestamps are therefore treated as missing, not silently coerced.
    """
    return value is not None and value.tzinfo is not None


def compute_event_id(
    *,
    event_type: str,
    subject_type: str,
    subject_value: str,
    timestamp: datetime,
    summary: str,
    value: str | None,
) -> str:
    """Content-addressed, deterministic event id.

    Hashes only stable evidence content — never the current time, a
    generation timestamp, a random UUID, or list position — so the same
    underlying evidence always produces the same id. Two evidence items
    that hash to the same id are, by construction, the same underlying
    observation; this is also the mechanism :func:`collect_events` uses to
    collapse duplicate evidence cited by more than one finding into one
    canonical event.
    """
    payload = "|".join(
        [
            event_type,
            subject_type,
            subject_value.strip().lower(),
            timestamp.isoformat(),
            summary.strip(),
            (value or "").strip(),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"evt_{digest}"


def sort_events(events: Iterable[TimelineEvent]) -> tuple[TimelineEvent, ...]:
    """Deterministic ordering: timestamp, then event type, then event id.

    Equal timestamps are broken by ``event_type`` and then by the
    content-addressed ``event_id`` — never by insertion or list position —
    so the same set of events always sorts into the same byte-identical
    sequence, regardless of the order they were collected in.
    """
    return tuple(sorted(events, key=lambda e: (e.timestamp, e.event_type.value, e.event_id)))


def collect_events(summary: InvestigationSummary) -> tuple[TimelineEvent, ...]:
    """Derive every timeline event from ``summary``'s findings' evidence.

    One canonical event per unique underlying evidence item: if the same
    evidence (identical type/subject/timestamp/summary/value) is cited by
    more than one finding, its content-addressed id is identical too, so
    every citation collapses into a single event whose ``evidence_references``
    lists every finding that cited it and whose ``severity`` is the worst
    (highest) severity among them. Evidence with no valid timestamp (see
    :func:`is_valid_evidence_timestamp`) is silently omitted — never
    estimated, never backfilled with the current time.
    """
    citations: dict[str, list[Finding]] = {}
    raw_by_id: dict[str, Evidence] = {}

    for finding in summary.findings:
        for weighted in finding.evidence:
            raw = weighted.evidence.evidence
            if not is_valid_evidence_timestamp(raw.observed_at):
                continue
            assert raw.observed_at is not None  # narrowed by the check above

            event_id = compute_event_id(
                event_type=raw.type.value,
                subject_type=finding.subject_type.value,
                subject_value=finding.subject_value,
                timestamp=raw.observed_at,
                summary=raw.summary,
                value=raw.value,
            )
            citations.setdefault(event_id, []).append(finding)
            raw_by_id.setdefault(event_id, raw)

    events: list[TimelineEvent] = []
    for event_id, citing_findings in citations.items():
        raw = raw_by_id[event_id]
        finding_ids = sorted({f.id for f in citing_findings})
        worst_severity: Severity = max(f.severity for f in citing_findings)
        assert raw.observed_at is not None  # every entry here passed the same check

        events.append(
            TimelineEvent(
                event_id=event_id,
                timestamp=raw.observed_at,
                event_type=raw.type,
                title=raw.summary,
                description=raw.value or "",
                source_type=TimelineSourceType.INVESTIGATION_EVIDENCE,
                source_id=finding_ids[0],
                severity=worst_severity,
                evidence_references=tuple(finding_ids),
            )
        )

    return sort_events(events)
