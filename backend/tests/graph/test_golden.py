"""Golden regression for the Graph Engine over the scenario corpus.

Snapshots every scenario's derived nodes and edges (excluding the source
summary's own ``generated_at``, which the ``EvidenceGraph`` wrapper merely
inherits and which is identity-independent here) so any unintended change to
canonicalization, deduplication, ordering, or identity turns CI red until the
golden is intentionally regenerated. Regenerate with
``THREATLENS_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from threatlens.graph.engine import GRAPH_ENGINE_VERSION, collect_graph

from .corpus import CORPUS, Scenario

_GOLDEN = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"


def _snapshot(scenario: Scenario) -> dict[str, Any]:
    """A stable, timestamp-format-independent view of one scenario's graph."""
    nodes, edges = collect_graph(scenario.summary, scenario.correlation)
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "label": n.label,
                "value": n.value,
                "severity": int(n.severity) if n.severity is not None else None,
                "source_references": list(n.source_references),
                "metadata": n.metadata,
            }
            for n in nodes
        ],
        "edges": [
            {
                "edge_id": e.edge_id,
                "source_node_id": e.source_node_id,
                "target_node_id": e.target_node_id,
                "relationship_type": e.relationship_type,
                "explanation": e.explanation,
                "evidence_references": list(e.evidence_references),
                "source_references": list(e.source_references),
            }
            for e in edges
        ],
    }


def _current_golden() -> dict[str, Any]:
    return {scenario.id: _snapshot(scenario) for scenario in CORPUS}


def test_corpus_ids_unique() -> None:
    ids = [s.id for s in CORPUS]
    assert len(ids) == len(set(ids))


def test_engine_version_unchanged() -> None:
    assert GRAPH_ENGINE_VERSION == "1.0"


def test_golden_regression() -> None:
    current = _current_golden()
    if _UPDATE:
        _GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("graph golden regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN.read_text())
    assert set(current) == set(golden), "corpus changed; regenerate the golden snapshot"
    drifted = [sid for sid in current if current[sid] != golden[sid]]
    assert not drifted, (
        "Graph output drifted for: "
        + ", ".join(drifted)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1 and bump the engine version)"
    )
