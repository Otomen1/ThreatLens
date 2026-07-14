"""Tests for the Investigation Timeline Engine (Phase 8.1).

These tests exist to make the brief's "Critical Design Rule" a checked fact,
not a comment: an event may exist only when backed by an explicit,
timezone-aware timestamp. No invented timestamps, no estimated chronology,
no inferred causality, no duplicate canonical events, stable ids, stable
ordering.
"""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.providers.results import EvidenceType
from threatlens.reasoning.models import FindingCategory, Severity
from threatlens.timeline.engine import (
    collect_events,
    compute_event_id,
    is_valid_evidence_timestamp,
    sort_events,
)
from threatlens.timeline.models import TimelineSourceType

from .factories import evidence, finding, summary

T1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
T2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC)
NAIVE = datetime(2024, 1, 3, 0, 0, 0)  # deliberately missing tzinfo


# --------------------------------------------------------------------------- #
# is_valid_evidence_timestamp
# --------------------------------------------------------------------------- #


class TestIsValidEvidenceTimestamp:
    def test_none_is_invalid(self) -> None:
        assert is_valid_evidence_timestamp(None) is False

    def test_naive_datetime_is_invalid(self) -> None:
        assert is_valid_evidence_timestamp(NAIVE) is False

    def test_aware_datetime_is_valid(self) -> None:
        assert is_valid_evidence_timestamp(T1) is True


# --------------------------------------------------------------------------- #
# collect_events — the critical design rule
# --------------------------------------------------------------------------- #


class TestCollectEventsTimestampPolicy:
    def test_valid_timestamp_produces_an_event(self) -> None:
        f = finding("f1", evidence_items=[evidence("Malicious per 3 feeds", T1)])
        events = collect_events(summary([f]))
        assert len(events) == 1
        assert events[0].timestamp == T1

    def test_missing_timestamp_is_omitted(self) -> None:
        f = finding("f1", evidence_items=[evidence("No timestamp reported", None)])
        events = collect_events(summary([f]))
        assert events == ()

    def test_naive_timestamp_is_omitted(self) -> None:
        """A naive datetime is treated as invalid, never coerced/assumed-UTC."""
        f = finding("f1", evidence_items=[evidence("Ambiguous timezone", NAIVE)])
        events = collect_events(summary([f]))
        assert events == ()

    def test_finding_with_no_evidence_produces_no_events(self) -> None:
        f = finding("f1", evidence_items=[])
        events = collect_events(summary([f]))
        assert events == ()

    def test_empty_investigation_yields_empty_timeline(self) -> None:
        assert collect_events(summary([])) == ()

    def test_mixed_valid_and_invalid_evidence(self) -> None:
        f = finding(
            "f1",
            evidence_items=[
                evidence("Valid", T1),
                evidence("Missing", None),
                evidence("Naive", NAIVE),
            ],
        )
        events = collect_events(summary([f]))
        assert len(events) == 1
        assert events[0].description == ""  # value defaults to None -> ""

    def test_never_reads_the_current_time(self) -> None:
        """No matter how many times this runs, results only ever reflect T1/T2 —
        proving no code path substitutes ``datetime.now()`` for a missing value."""
        f = finding("f1", evidence_items=[evidence("Valid", T1), evidence("Missing", None)])
        for _ in range(3):
            events = collect_events(summary([f]))
            assert [e.timestamp for e in events] == [T1]


class TestCollectEventsContent:
    def test_event_type_reuses_evidence_type(self) -> None:
        f = finding(
            "f1", evidence_items=[evidence("First seen", T1, evidence_type=EvidenceType.FIRST_SEEN)]
        )
        events = collect_events(summary([f]))
        assert events[0].event_type == EvidenceType.FIRST_SEEN

    def test_title_is_the_evidence_summary_verbatim(self) -> None:
        f = finding("f1", evidence_items=[evidence("Reported by AbuseIPDB", T1)])
        events = collect_events(summary([f]))
        assert events[0].title == "Reported by AbuseIPDB"

    def test_description_is_the_evidence_value_verbatim(self) -> None:
        f = finding("f1", evidence_items=[evidence("Confidence score", T1, value="95")])
        events = collect_events(summary([f]))
        assert events[0].description == "95"

    def test_source_type_is_investigation_evidence(self) -> None:
        f = finding("f1", evidence_items=[evidence("x", T1)])
        events = collect_events(summary([f]))
        assert events[0].source_type == TimelineSourceType.INVESTIGATION_EVIDENCE

    def test_source_id_and_references_point_to_the_finding(self) -> None:
        f = finding("f1", evidence_items=[evidence("x", T1)])
        events = collect_events(summary([f]))
        assert events[0].source_id == "f1"
        assert events[0].evidence_references == ("f1",)

    def test_severity_copied_from_finding_never_recomputed(self) -> None:
        f = finding("f1", severity=Severity.CRITICAL, evidence_items=[evidence("x", T1)])
        events = collect_events(summary([f]))
        assert events[0].severity == Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Deduplication — one canonical event per unique underlying evidence item
# --------------------------------------------------------------------------- #


class TestDeduplication:
    def test_identical_evidence_cited_by_two_findings_collapses_to_one_event(self) -> None:
        shared = evidence("Reported malicious by 3 blocklists", T1, value="95")
        f1 = finding("f1", severity=Severity.HIGH, evidence_items=[shared])
        f2 = finding("f2", severity=Severity.MEDIUM, evidence_items=[shared])
        events = collect_events(summary([f1, f2]))
        assert len(events) == 1

    def test_deduplicated_event_references_every_citing_finding(self) -> None:
        shared = evidence("Reported malicious by 3 blocklists", T1, value="95")
        f1 = finding("f1", evidence_items=[shared])
        f2 = finding("f2", evidence_items=[shared])
        events = collect_events(summary([f1, f2]))
        assert events[0].evidence_references == ("f1", "f2")

    def test_deduplicated_event_takes_the_worst_severity(self) -> None:
        shared = evidence("Reported malicious by 3 blocklists", T1, value="95")
        f1 = finding("f1", severity=Severity.HIGH, evidence_items=[shared])
        f2 = finding("f2", severity=Severity.CRITICAL, evidence_items=[shared])
        events = collect_events(summary([f1, f2]))
        assert events[0].severity == Severity.CRITICAL

    def test_source_id_is_the_lexicographically_smallest_finding_id(self) -> None:
        shared = evidence("Reported malicious by 3 blocklists", T1, value="95")
        f_z = finding("z_finding", evidence_items=[shared])
        f_a = finding("a_finding", evidence_items=[shared])
        events = collect_events(summary([f_z, f_a]))
        assert events[0].source_id == "a_finding"

    def test_distinct_evidence_on_the_same_subject_is_not_merged(self) -> None:
        f1 = finding("f1", evidence_items=[evidence("Malicious", T1, value="A")])
        f2 = finding("f2", evidence_items=[evidence("Malicious", T1, value="B")])
        events = collect_events(summary([f1, f2]))
        assert len(events) == 2  # differing `value` makes these distinct observations

    def test_same_evidence_content_on_different_subjects_is_not_merged(self) -> None:
        f1 = finding("f1", subject_value="1.1.1.1", evidence_items=[evidence("Malicious", T1)])
        f2 = finding("f2", subject_value="2.2.2.2", evidence_items=[evidence("Malicious", T1)])
        events = collect_events(summary([f1, f2]))
        assert len(events) == 2


# --------------------------------------------------------------------------- #
# Multiple evidence sources within one investigation
# --------------------------------------------------------------------------- #


class TestMultipleEvidenceSources:
    def test_multiple_findings_each_with_distinct_evidence(self) -> None:
        f1 = finding("f1", evidence_items=[evidence("A", T1)])
        f2 = finding(
            "f2",
            categories=[FindingCategory.REPUTATION],
            evidence_items=[evidence("B", T2)],
        )
        events = collect_events(summary([f1, f2]))
        assert len(events) == 2

    def test_one_finding_with_multiple_evidence_items(self) -> None:
        f = finding("f1", evidence_items=[evidence("A", T1), evidence("B", T2)])
        events = collect_events(summary([f]))
        assert len(events) == 2


# --------------------------------------------------------------------------- #
# compute_event_id — content-addressed identity
# --------------------------------------------------------------------------- #


class TestComputeEventId:
    def _args(self, **overrides: object) -> dict[str, object]:
        defaults: dict[str, object] = {
            "event_type": "classification",
            "subject_type": "ipv4",
            "subject_value": "1.2.3.4",
            "timestamp": T1,
            "summary": "Malicious",
            "value": None,
        }
        defaults.update(overrides)
        return defaults

    def test_deterministic_for_identical_input(self) -> None:
        assert compute_event_id(**self._args()) == compute_event_id(**self._args())  # type: ignore[arg-type]

    def test_differs_when_timestamp_differs(self) -> None:
        a = compute_event_id(**self._args())  # type: ignore[arg-type]
        b = compute_event_id(**self._args(timestamp=T2))  # type: ignore[arg-type]
        assert a != b

    def test_differs_when_event_type_differs(self) -> None:
        a = compute_event_id(**self._args())  # type: ignore[arg-type]
        b = compute_event_id(**self._args(event_type="first_seen"))  # type: ignore[arg-type]
        assert a != b

    def test_differs_when_subject_differs(self) -> None:
        a = compute_event_id(**self._args())  # type: ignore[arg-type]
        b = compute_event_id(**self._args(subject_value="9.9.9.9"))  # type: ignore[arg-type]
        assert a != b

    def test_subject_value_is_case_insensitive(self) -> None:
        a = compute_event_id(**self._args(subject_value="Example.COM"))  # type: ignore[arg-type]
        b = compute_event_id(**self._args(subject_value="example.com"))  # type: ignore[arg-type]
        assert a == b

    def test_never_includes_current_time(self) -> None:
        """Calling twice, moments apart, must still produce the same id."""
        import time

        a = compute_event_id(**self._args())  # type: ignore[arg-type]
        time.sleep(0.01)
        b = compute_event_id(**self._args())  # type: ignore[arg-type]
        assert a == b

    def test_prefixed_and_stable_length(self) -> None:
        event_id = compute_event_id(**self._args())  # type: ignore[arg-type]
        assert event_id.startswith("evt_")
        assert len(event_id) == len("evt_") + 16


# --------------------------------------------------------------------------- #
# sort_events — deterministic ordering
# --------------------------------------------------------------------------- #


class TestSortEvents:
    def test_orders_by_timestamp_ascending(self) -> None:
        f = finding("f1", evidence_items=[evidence("Later", T2), evidence("Earlier", T1)])
        events = collect_events(summary([f]))
        assert [e.timestamp for e in events] == [T1, T2]

    def test_equal_timestamps_break_ties_by_event_type_then_id(self) -> None:
        f = finding(
            "f1",
            evidence_items=[
                evidence("Z", T1, evidence_type=EvidenceType.TAG, value="1"),
                evidence("A", T1, evidence_type=EvidenceType.BLOCKLIST, value="2"),
            ],
        )
        events = collect_events(summary([f]))
        # "blocklist" < "tag" lexicographically -> BLOCKLIST-typed event sorts first
        assert [e.event_type for e in events] == [EvidenceType.BLOCKLIST, EvidenceType.TAG]

    def test_equal_timestamp_and_type_break_ties_by_event_id(self) -> None:
        f = finding(
            "f1",
            evidence_items=[
                evidence("Malicious", T1, value="A"),
                evidence("Malicious", T1, value="B"),
            ],
        )
        events = collect_events(summary([f]))
        assert len(events) == 2
        assert events[0].event_id < events[1].event_id

    def test_reordering_input_evidence_does_not_change_output_order(self) -> None:
        e1 = evidence("A", T1, value="A")
        e2 = evidence("B", T2, value="B")
        forward = collect_events(summary([finding("f1", evidence_items=[e1, e2])]))
        backward = collect_events(summary([finding("f1", evidence_items=[e2, e1])]))
        assert forward == backward

    def test_sort_events_is_pure_and_repeatable(self) -> None:
        f = finding("f1", evidence_items=[evidence("A", T2), evidence("B", T1)])
        events = collect_events(summary([f]))
        assert sort_events(events) == sort_events(reversed(events))


# --------------------------------------------------------------------------- #
# Read-only behavior — the input is never mutated
# --------------------------------------------------------------------------- #


class TestReadOnly:
    def test_input_summary_unchanged_after_collection(self) -> None:
        f = finding("f1", evidence_items=[evidence("A", T1)])
        source = summary([f])
        before = source.model_dump_json()
        collect_events(source)
        after = source.model_dump_json()
        assert before == after
