"""Tests for Evidence Relationship Graph models (Phase 8.2).

Covers the graph's own vocabulary and envelope. Node/edge-derivation logic
lives in the engine and is tested in ``test_engine.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from threatlens.entities.types import EntityType
from threatlens.graph import EvidenceGraph, GraphEdge, GraphNode
from threatlens.reasoning import Severity

NOW = datetime(2024, 1, 1, tzinfo=UTC)


def _node(**overrides: object) -> GraphNode:
    defaults: dict[str, object] = {
        "node_id": "node_test",
        "node_type": "ipv4",
        "label": "1.2.3.4",
        "value": "1.2.3.4",
    }
    defaults.update(overrides)
    return GraphNode(**defaults)  # type: ignore[arg-type]


def _edge(**overrides: object) -> GraphEdge:
    defaults: dict[str, object] = {
        "edge_id": "edge_test",
        "source_node_id": "node_a",
        "target_node_id": "node_b",
        "relationship_type": "associated_with",
    }
    defaults.update(overrides)
    return GraphEdge(**defaults)  # type: ignore[arg-type]


class TestGraphNode:
    def test_defaults(self) -> None:
        node = _node()
        assert node.severity is None
        assert node.source_references == ()
        assert node.metadata == {}

    def test_blank_node_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _node(node_id="")

    def test_blank_node_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _node(node_type="")

    def test_blank_label_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _node(label="")

    def test_blank_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _node(value="")

    def test_severity_reused_not_duplicated(self) -> None:
        node = _node(severity=Severity.CRITICAL)
        assert node.severity is Severity.CRITICAL

    def test_frozen(self) -> None:
        node = _node()
        with pytest.raises(ValidationError):
            node.label = "changed"  # type: ignore[misc]

    def test_round_trips_through_json(self) -> None:
        node = _node(source_references=("f1", "f2"), metadata={"rule_id": "r1"})
        restored = GraphNode.model_validate_json(node.model_dump_json())
        assert restored == node


class TestGraphEdge:
    def test_defaults(self) -> None:
        edge = _edge()
        assert edge.explanation == ""
        assert edge.evidence_references == ()
        assert edge.source_references == ()

    def test_blank_edge_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _edge(edge_id="")

    def test_blank_relationship_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _edge(relationship_type="")

    def test_frozen(self) -> None:
        edge = _edge()
        with pytest.raises(ValidationError):
            edge.explanation = "changed"  # type: ignore[misc]

    def test_round_trips_through_json(self) -> None:
        edge = _edge(evidence_references=("f1",), source_references=("cor_1",))
        restored = GraphEdge.model_validate_json(edge.model_dump_json())
        assert restored == edge


class TestEvidenceGraph:
    def test_defaults(self) -> None:
        graph = EvidenceGraph(
            investigation_id=uuid4(),
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            generated_at=NOW,
            node_count=0,
            edge_count=0,
            graph_version="1.0",
        )
        assert graph.nodes == ()
        assert graph.edges == ()
        assert graph.is_empty is True

    def test_is_empty_false_with_nodes(self) -> None:
        graph = EvidenceGraph(
            investigation_id=uuid4(),
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            generated_at=NOW,
            nodes=(_node(),),
            node_count=1,
            edge_count=0,
            graph_version="1.0",
        )
        assert graph.is_empty is False

    def test_frozen(self) -> None:
        graph = EvidenceGraph(
            investigation_id=uuid4(),
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            generated_at=NOW,
            node_count=0,
            edge_count=0,
            graph_version="1.0",
        )
        with pytest.raises(ValidationError):
            graph.entity_value = "changed"  # type: ignore[misc]

    def test_negative_counts_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceGraph(
                investigation_id=uuid4(),
                entity_type=EntityType.IPV4,
                entity_value="1.2.3.4",
                generated_at=NOW,
                node_count=-1,
                edge_count=0,
                graph_version="1.0",
            )
