"""Tests for ReportService (Phase 8.4): composing Timeline + Graph.

``ReportService`` owns no event/node-derivation logic of its own — that
belongs to Timeline's and Graph's own engines, already exhaustively tested
in their own suites. These tests only prove correct composition:
determinism, non-mutation, and that each section is exactly what the
sibling ``TimelineService``/``GraphService`` independently produce.
"""

from __future__ import annotations

from threatlens.graph import GraphService
from threatlens.reporting import REPORTING_FRAMEWORK_VERSION, ReportService
from threatlens.timeline import TimelineService

from .factories import finding, record, summary


def _service() -> ReportService:
    return ReportService(TimelineService(), GraphService())


class TestBuildWithoutSummary:
    def test_investigation_is_the_saved_record_verbatim(self) -> None:
        rec = record()
        report = _service().build(rec)
        assert report.investigation == rec

    def test_timeline_is_empty(self) -> None:
        report = _service().build(record())
        assert report.timeline.is_empty

    def test_graph_is_empty(self) -> None:
        report = _service().build(record())
        assert report.graph.is_empty

    def test_schema_version_is_set(self) -> None:
        report = _service().build(record())
        assert report.report_schema_version == REPORTING_FRAMEWORK_VERSION


class TestBuildWithSummary:
    def _record_with_finding(self) -> object:
        s = summary([finding("f1")])
        return record(investigation_summary=s)

    def test_timeline_matches_the_independent_timeline_service(self) -> None:
        """The report's timeline section is not a re-derivation — it is
        exactly what the sibling /timeline endpoint's own service produces."""
        rec = self._record_with_finding()
        report = _service().build(rec)
        assert report.timeline == TimelineService().build(rec)

    def test_graph_matches_the_independent_graph_service(self) -> None:
        """Same guarantee for the graph section, against GraphService."""
        rec = self._record_with_finding()
        report = _service().build(rec)
        assert report.graph == GraphService().build(rec)

    def test_investigation_summary_is_attached_verbatim(self) -> None:
        rec = self._record_with_finding()
        report = _service().build(rec)
        assert report.investigation.investigation_summary == rec.investigation_summary


class TestDeterminismAndSafety:
    def test_repeated_build_is_byte_identical(self) -> None:
        rec = record(investigation_summary=summary([finding("f1")]))
        service = _service()
        assert service.build(rec) == service.build(rec)

    def test_does_not_mutate_the_saved_record(self) -> None:
        rec = record(investigation_summary=summary([finding("f1")]))
        before = rec.model_dump_json()
        _service().build(rec)
        after = rec.model_dump_json()
        assert before == after

    def test_a_second_service_instance_produces_the_same_report(self) -> None:
        """No hidden per-instance state — two independently constructed
        ReportServices agree on the same saved record."""
        rec = record(investigation_summary=summary([finding("f1")]))
        assert _service().build(rec) == _service().build(rec)
