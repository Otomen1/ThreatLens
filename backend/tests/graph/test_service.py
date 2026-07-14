"""Tests for GraphService (Phase 8.2): adapting a saved WorkspaceInvestigation.

The service owns no node/edge-derivation logic of its own (that's
``test_engine.py``'s job) — only "which field of a saved record feeds the
graph."
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from threatlens.entities.types import EntityType
from threatlens.graph import GraphService
from threatlens.workspace import WorkspaceInvestigation

from .factories import (
    correlation_evidence,
    correlation_summary,
    finding,
    observation,
    relationship,
    summary,
)

CREATED = datetime(2024, 1, 1, tzinfo=UTC)
UPDATED = datetime(2024, 1, 2, tzinfo=UTC)
SUMMARY_TIME = datetime(2024, 1, 3, tzinfo=UTC)


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
    def test_returns_an_empty_graph(self) -> None:
        record = _record()
        graph = GraphService().build(record)
        assert graph.is_empty

    def test_uses_record_investigation_type(self) -> None:
        record = _record(investigation_type=EntityType.DOMAIN)
        graph = GraphService().build(record)
        assert graph.entity_type == EntityType.DOMAIN

    def test_entity_value_is_empty_string(self) -> None:
        record = _record()
        graph = GraphService().build(record)
        assert graph.entity_value == ""

    def test_generated_at_falls_back_to_record_updated_at(self) -> None:
        record = _record()
        graph = GraphService().build(record)
        assert graph.generated_at == UPDATED

    def test_investigation_id_matches_the_record(self) -> None:
        record = _record()
        graph = GraphService().build(record)
        assert graph.investigation_id == record.id

    def test_counts_are_zero(self) -> None:
        record = _record()
        graph = GraphService().build(record)
        assert graph.node_count == 0
        assert graph.edge_count == 0


class TestBuildWithSummary:
    def _summary_with_one_edge(self) -> object:
        f = finding("f1", relationships=[relationship()])
        return summary([f], entity_value="9.9.9.9", generated_at=SUMMARY_TIME)

    def test_derives_nodes_and_edges_from_the_attached_summary(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_edge())
        graph = GraphService().build(record)
        assert graph.node_count == 2
        assert graph.edge_count == 1

    def test_entity_type_and_value_come_from_the_summary(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_edge())
        graph = GraphService().build(record)
        assert graph.entity_type == EntityType.IPV4
        assert graph.entity_value == "9.9.9.9"

    def test_generated_at_comes_from_the_summary_not_the_record(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_edge())
        graph = GraphService().build(record)
        assert graph.generated_at == SUMMARY_TIME
        assert graph.generated_at != UPDATED

    def test_does_not_mutate_the_saved_record(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_edge())
        before = record.model_dump_json()
        GraphService().build(record)
        after = record.model_dump_json()
        assert before == after

    def test_repeated_build_is_byte_identical(self) -> None:
        record = _record(investigation_summary=self._summary_with_one_edge())
        service = GraphService()
        assert service.build(record) == service.build(record)


class TestBuildWithCorrelation:
    def test_correlation_observations_contribute_nodes_and_edges(self) -> None:
        # finding("f1") and correlation_evidence("f1") share the same default
        # subject (8.8.8.8) — exactly like the real engine, which always
        # copies CorrelationEvidence.subject_* from the finding it cites.
        s = summary([finding("f1")])
        corr = correlation_summary(
            [observation("cor_1", evidence_items=[correlation_evidence("f1")])]
        )
        record = _record(investigation_summary=s, correlation_summary=corr)
        graph = GraphService().build(record)
        assert graph.node_count == 2  # the entity + the observation
        assert graph.edge_count == 1  # the hub edge

    def test_correlation_alone_without_summary_is_handled_gracefully(self) -> None:
        """WorkspaceInvestigation permits correlation_summary without an
        investigation_summary; the service must not crash on this state."""
        corr = correlation_summary(
            [observation("cor_1", evidence_items=[correlation_evidence("f1")])]
        )
        record = _record(correlation_summary=corr)
        graph = GraphService().build(record)
        assert graph.node_count == 2
        assert graph.entity_value == ""  # falls back exactly like the no-summary case
