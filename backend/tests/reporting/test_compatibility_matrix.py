"""Platform compatibility matrix (Phase 8.5).

Timeline, EvidenceGraph, and InvestigationReport are pure projections over a
saved WorkspaceInvestigation's three optional sections
(``investigation_summary``, ``correlation_summary``, ``detection_package``),
each attached — or not — independently of the others. The existing suites
(``tests/timeline/test_engine.py``, ``tests/graph/test_engine.py``,
``tests/reporting/test_service.py``) already exhaustively test one axis at a
time (e.g. "no summary", "correlation alone", "multiple findings"); this file
sweeps the *combination* of shapes a real saved record can have and proves
the derived projections stay well-formed and mutually independent across all
of them, both at the service layer and through the real HTTP API. Not new
derivation logic — a cross-cutting check that no combination raises or
produces an inconsistent shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.workspace import (
    get_graph_service,
    get_report_service,
    get_timeline_service,
    get_workspace_service,
)
from threatlens.correlation.models import (
    CorrelationCategory,
    CorrelationEvidence,
    CorrelationMetadata,
    CorrelationObservation,
    CorrelationStatistics,
    CorrelationSummary,
)
from threatlens.detection.models import DetectionMetadata, DetectionPackage
from threatlens.entities.types import EntityType
from threatlens.graph import GraphService
from threatlens.providers.aggregation import AttributedEvidence
from threatlens.providers.results import Evidence, EvidenceType
from threatlens.reasoning.models import (
    EvidenceDimension,
    EvidencePolarity,
    FindingCategory,
    WeightedEvidence,
)
from threatlens.reporting import ReportService
from threatlens.timeline import TimelineService
from threatlens.workspace import LocalFileStorage, WorkspaceInvestigation, WorkspaceService

from .factories import finding, record, summary

NOW = datetime(2024, 1, 1, tzinfo=UTC)


def _timestamped_evidence(summary_text: str = "observed") -> WeightedEvidence:
    """One piece of evidence with an explicit, timezone-aware timestamp — the
    only kind Timeline derives an event from (see ``timeline/engine.py``)."""
    raw = Evidence(type=EvidenceType.CLASSIFICATION, summary=summary_text, observed_at=NOW)
    return WeightedEvidence(
        evidence=AttributedEvidence(evidence=raw, sources=["test_provider"]),
        weight=1.0,
        polarity=EvidencePolarity.SUPPORTING,
        dimension=EvidenceDimension.REPUTATION,
    )


def _correlation() -> CorrelationSummary:
    evidence = CorrelationEvidence(
        finding_id="f1",
        matched_category=FindingCategory.MALICIOUS_INFRASTRUCTURE,
        subject_type=EntityType.IPV4,
        subject_value="8.8.8.8",
        summary="matched",
    )
    obs = CorrelationObservation(
        id="obs1",
        rule_id="test_rule",
        category=CorrelationCategory.MALICIOUS_EXPOSED_INFRASTRUCTURE,
        title="Test observation",
        subject_type=EntityType.IPV4,
        subject_value="8.8.8.8",
        evidence=(evidence,),
        relationships=(),
        source_finding_ids=("f1",),
    )
    return CorrelationSummary(
        id="cor_test_summary",
        entity_type=EntityType.IPV4,
        entity_value="8.8.8.8",
        observations=(obs,),
        matches=(),
        statistics=CorrelationStatistics(total_observations=1),
        metadata=CorrelationMetadata(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            generated_at=NOW,
            framework_version="test",
            source_engine_version="test",
        ),
        source_finding_ids=("f1",),
    )


def _detection_package() -> DetectionPackage:
    return DetectionPackage(
        id="package-1",
        metadata=DetectionMetadata(
            engine_version="1.0",
            source_engine_version="1.0",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            generated_at=NOW,
        ),
    )


def _scenarios() -> list[tuple[str, WorkspaceInvestigation]]:
    """Representative saved-record shapes spanning every optional-section combination."""
    finding_with_evidence = finding("f1", evidence=[_timestamped_evidence()])
    return [
        ("bare", record()),
        ("detection_only", record(detection_package=_detection_package())),
        (
            "single_finding",
            record(investigation_summary=summary([finding_with_evidence])),
        ),
        (
            "multiple_findings",
            record(
                investigation_summary=summary(
                    [
                        finding_with_evidence,
                        finding("f2", subject_value="1.1.1.1", evidence=[_timestamped_evidence()]),
                    ]
                )
            ),
        ),
        ("correlation_only", record(correlation_summary=_correlation())),
        (
            "fully_populated",
            record(
                investigation_summary=summary([finding_with_evidence]),
                correlation_summary=_correlation(),
                detection_package=_detection_package(),
            ),
        ),
    ]


_SCENARIOS = _scenarios()
_SCENARIO_IDS = [name for name, _ in _SCENARIOS]
_matrix = pytest.mark.parametrize("name,rec", _SCENARIOS, ids=_SCENARIO_IDS)


class TestProjectionsAgreeAcrossEveryShape:
    """Service-level: every shape stays internally consistent and matches its
    own dedicated service — never diverges, never raises."""

    @_matrix
    def test_timeline_is_empty_iff_no_summary(self, name: str, rec: WorkspaceInvestigation) -> None:
        timeline = TimelineService().build(rec)
        assert timeline.is_empty == (rec.investigation_summary is None)

    @_matrix
    def test_graph_is_empty_iff_no_summary_and_no_correlation(
        self, name: str, rec: WorkspaceInvestigation
    ) -> None:
        graph = GraphService().build(rec)
        expected_empty = rec.investigation_summary is None and rec.correlation_summary is None
        assert graph.is_empty == expected_empty

    @_matrix
    def test_report_timeline_matches_the_independent_timeline_service(
        self, name: str, rec: WorkspaceInvestigation
    ) -> None:
        report = ReportService(TimelineService(), GraphService()).build(rec)
        assert report.timeline == TimelineService().build(rec)

    @_matrix
    def test_report_graph_matches_the_independent_graph_service(
        self, name: str, rec: WorkspaceInvestigation
    ) -> None:
        report = ReportService(TimelineService(), GraphService()).build(rec)
        assert report.graph == GraphService().build(rec)

    @_matrix
    def test_detection_package_is_preserved_regardless_of_other_sections(
        self, name: str, rec: WorkspaceInvestigation
    ) -> None:
        """Timeline/Graph derivation never reads ``detection_package``; its
        presence or absence must never affect whether it survives verbatim in
        the report envelope."""
        report = ReportService(TimelineService(), GraphService()).build(rec)
        assert report.investigation.detection_package == rec.detection_package


@pytest.fixture()
def client(tmp_path: Path):
    workspace_service = WorkspaceService(LocalFileStorage(tmp_path))
    timeline_service = TimelineService()
    graph_service = GraphService()
    app.dependency_overrides[get_workspace_service] = lambda: workspace_service
    app.dependency_overrides[get_timeline_service] = lambda: timeline_service
    app.dependency_overrides[get_graph_service] = lambda: graph_service
    app.dependency_overrides[get_report_service] = lambda: ReportService(
        timeline_service, graph_service
    )
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)
    app.dependency_overrides.pop(get_timeline_service, None)
    app.dependency_overrides.pop(get_graph_service, None)
    app.dependency_overrides.pop(get_report_service, None)


class TestApiAgreesAcrossEveryShape:
    """HTTP-level: the same matrix, round-tripped through real JSON
    (de)serialization — every shape a saved record can have must save and
    export cleanly over the wire, not just as in-memory Python objects."""

    @_matrix
    def test_save_and_export_round_trip(
        self, name: str, rec: WorkspaceInvestigation, client: TestClient
    ) -> None:
        body = {
            "title": "Matrix case",
            "investigation_type": rec.investigation_type.value,
        }
        if rec.investigation_summary is not None:
            body["investigation_summary"] = rec.investigation_summary.model_dump(mode="json")
        if rec.correlation_summary is not None:
            body["correlation_summary"] = rec.correlation_summary.model_dump(mode="json")
        if rec.detection_package is not None:
            body["detection_package"] = rec.detection_package.model_dump(mode="json")

        saved = client.post("/api/v1/workspace", json=body)
        assert saved.status_code == 201, saved.text
        investigation_id = saved.json()["id"]

        res = client.get(f"/api/v1/workspace/{investigation_id}/export")
        assert res.status_code == 200
        exported = res.json()
        assert (exported["investigation"]["detection_package"] is None) == (
            rec.detection_package is None
        )
        assert (exported["timeline"]["events"] == []) == (rec.investigation_summary is None)
        assert (exported["graph"]["nodes"] == []) == (
            rec.investigation_summary is None and rec.correlation_summary is None
        )

        client.delete(f"/api/v1/workspace/{investigation_id}")
