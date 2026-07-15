"""Tests for InvestigationReport (Phase 8.4): the envelope itself."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from threatlens.graph import GraphService
from threatlens.reporting import REPORTING_FRAMEWORK_VERSION, InvestigationReport
from threatlens.timeline import TimelineService

from .factories import record


def _report() -> InvestigationReport:
    rec = record()
    return InvestigationReport(
        report_schema_version=REPORTING_FRAMEWORK_VERSION,
        investigation=rec,
        timeline=TimelineService().build(rec),
        graph=GraphService().build(rec),
    )


class TestInvestigationReport:
    def test_is_frozen(self) -> None:
        report = _report()
        with pytest.raises(ValidationError):
            report.report_schema_version = "2.0"  # type: ignore[misc]

    def test_requires_a_non_empty_schema_version(self) -> None:
        rec = record()
        with pytest.raises(ValidationError):
            InvestigationReport(
                report_schema_version="",
                investigation=rec,
                timeline=TimelineService().build(rec),
                graph=GraphService().build(rec),
            )

    def test_carries_the_investigation_timeline_and_graph_verbatim(self) -> None:
        rec = record()
        timeline = TimelineService().build(rec)
        graph = GraphService().build(rec)
        report = InvestigationReport(
            report_schema_version=REPORTING_FRAMEWORK_VERSION,
            investigation=rec,
            timeline=timeline,
            graph=graph,
        )
        assert report.investigation == rec
        assert report.timeline == timeline
        assert report.graph == graph

    def test_json_round_trips(self) -> None:
        report = _report()
        restored = InvestigationReport.model_validate_json(report.model_dump_json())
        assert restored == report
