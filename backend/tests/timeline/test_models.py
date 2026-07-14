"""Tests for Investigation Timeline models (Phase 8.1).

Covers the timeline's own vocabulary and envelope. Evidence-derivation logic
lives in the engine and is tested in ``test_engine.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from threatlens.entities.types import EntityType
from threatlens.providers.results import EvidenceType
from threatlens.reasoning import Severity
from threatlens.timeline import Timeline, TimelineEvent, TimelineSourceType

NOW = datetime(2024, 1, 1, tzinfo=UTC)


def _event(**overrides: object) -> TimelineEvent:
    defaults: dict[str, object] = {
        "event_id": "evt_test",
        "timestamp": NOW,
        "event_type": EvidenceType.CLASSIFICATION,
        "title": "Test event",
        "source_type": TimelineSourceType.INVESTIGATION_EVIDENCE,
        "source_id": "fnd_1",
    }
    defaults.update(overrides)
    return TimelineEvent(**defaults)  # type: ignore[arg-type]


class TestTimelineSourceType:
    def test_only_investigation_evidence_populated_in_phase_8_1(self) -> None:
        assert {t.value for t in TimelineSourceType} == {"investigation_evidence"}


class TestTimelineEvent:
    def test_defaults(self) -> None:
        event = _event()
        assert event.description == ""
        assert event.severity is None
        assert event.evidence_references == ()

    def test_blank_title_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _event(title="")

    def test_blank_event_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _event(event_id="")

    def test_blank_source_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _event(source_id="")

    def test_severity_reused_not_duplicated(self) -> None:
        event = _event(severity=Severity.CRITICAL)
        assert event.severity is Severity.CRITICAL

    def test_frozen(self) -> None:
        event = _event()
        with pytest.raises(ValidationError):
            event.title = "changed"  # type: ignore[misc]

    def test_round_trips_through_json(self) -> None:
        event = _event(evidence_references=("fnd_1", "fnd_2"), severity=Severity.HIGH)
        restored = TimelineEvent.model_validate_json(event.model_dump_json())
        assert restored == event


class TestTimeline:
    def test_defaults(self) -> None:
        timeline = Timeline(
            investigation_id=uuid4(),
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            generated_at=NOW,
        )
        assert timeline.events == ()
        assert timeline.is_empty is True

    def test_is_empty_false_with_events(self) -> None:
        timeline = Timeline(
            investigation_id=uuid4(),
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            generated_at=NOW,
            events=(_event(),),
        )
        assert timeline.is_empty is False

    def test_frozen(self) -> None:
        timeline = Timeline(
            investigation_id=uuid4(),
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            generated_at=NOW,
        )
        with pytest.raises(ValidationError):
            timeline.entity_value = "changed"  # type: ignore[misc]
