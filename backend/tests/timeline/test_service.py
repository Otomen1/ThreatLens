"""Tests for TimelineService (Phase 8.1): adapting a saved WorkspaceInvestigation.

The service owns no evidence-derivation logic of its own (that's
``test_engine.py``'s job) — only "which field of a saved record feeds which
part of the timeline."
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from threatlens.entities.types import EntityType
from threatlens.timeline import TimelineService
from threatlens.workspace import WorkspaceInvestigation

from .factories import evidence, finding, summary

CREATED = datetime(2024, 1, 1, tzinfo=UTC)
UPDATED = datetime(2024, 1, 2, tzinfo=UTC)
EVIDENCE_TIME = datetime(2024, 1, 3, tzinfo=UTC)


def _record(**overrides: object) -> WorkspaceInvestigation:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "title": "Case",
        "created_at": CREATED,
        "updated_at": UPDATED,
        "investigation_type": EntityType.IPV4,
    }
    defaults.update(overrides)
    return WorkspaceInvestigation(**defaults)  # type: ignore[arg-type]


class TestBuildWithoutSummary:
    def test_returns_an_empty_timeline(self) -> None:
        record = _record()
        timeline = TimelineService().build(record)
        assert timeline.is_empty

    def test_uses_record_investigation_type(self) -> None:
        record = _record(investigation_type=EntityType.DOMAIN)
        timeline = TimelineService().build(record)
        assert timeline.entity_type == EntityType.DOMAIN

    def test_entity_value_is_empty_string(self) -> None:
        record = _record()
        timeline = TimelineService().build(record)
        assert timeline.entity_value == ""

    def test_generated_at_falls_back_to_record_updated_at(self) -> None:
        record = _record()
        timeline = TimelineService().build(record)
        assert timeline.generated_at == UPDATED

    def test_investigation_id_matches_the_record(self) -> None:
        record = _record()
        timeline = TimelineService().build(record)
        assert timeline.investigation_id == record.id


class TestBuildWithSummary:
    def _summary_with_one_event(self) -> object:
        f = finding("f1", evidence_items=[evidence("Malicious", EVIDENCE_TIME)])
        return summary([f], entity_value="9.9.9.9", generated_at=EVIDENCE_TIME)

    def test_derives_events_from_the_attached_summary(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_event())
        timeline = TimelineService().build(record)
        assert len(timeline.events) == 1
        assert timeline.events[0].timestamp == EVIDENCE_TIME

    def test_entity_type_and_value_come_from_the_summary(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_event())
        timeline = TimelineService().build(record)
        assert timeline.entity_type == EntityType.IPV4
        assert timeline.entity_value == "9.9.9.9"

    def test_generated_at_comes_from_the_summary_not_the_record(self) -> None:
        """The summary's own generated_at wins over the record's updated_at —
        proving the fallback in TestBuildWithoutSummary is truly a fallback."""
        record = _record(investigation_summary=self._summary_with_one_event())
        timeline = TimelineService().build(record)
        assert timeline.generated_at == EVIDENCE_TIME
        assert timeline.generated_at != UPDATED

    def test_does_not_mutate_the_saved_record(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_event())
        before = record.model_dump_json()
        TimelineService().build(record)
        after = record.model_dump_json()
        assert before == after

    def test_repeated_build_is_byte_identical(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_event())
        service = TimelineService()
        assert service.build(record) == service.build(record)
