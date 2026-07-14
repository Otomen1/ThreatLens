"""Evidence Relationship Graph Framework (Phase 8.2).

A pure, deterministic, read-only consumer of a saved investigation's already
computed :class:`~threatlens.reasoning.models.InvestigationSummary` and
:class:`~threatlens.correlation.models.CorrelationSummary`. It derives a graph
of entities and their explicit relationships — never an invented entity,
never an inferred relationship, never a connection drawn merely because two
things co-occur in the same investigation. No AI, no probabilistic
inference, no new intelligence engine.

There is no ``exceptions.py``: like the Timeline Framework (Phase 8.1), the
graph is always derivable — a saved investigation with no attached
``investigation_summary``/``correlation_summary`` yields a well-formed empty
graph rather than an error — so there is no failure mode of this framework's
own to name. See ``docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md``.
"""

from __future__ import annotations

from .engine import (
    CORRELATED_WITH,
    GRAPH_ENGINE_VERSION,
    OBSERVATION_NODE_TYPE,
    collect_graph,
    compute_edge_id,
    compute_node_id,
    sort_edges,
    sort_nodes,
)
from .models import GRAPH_FRAMEWORK_VERSION, EvidenceGraph, GraphEdge, GraphNode
from .service import GraphService

__all__ = [
    "CORRELATED_WITH",
    "GRAPH_ENGINE_VERSION",
    "GRAPH_FRAMEWORK_VERSION",
    "OBSERVATION_NODE_TYPE",
    "EvidenceGraph",
    "GraphEdge",
    "GraphNode",
    "GraphService",
    "collect_graph",
    "compute_edge_id",
    "compute_node_id",
    "sort_edges",
    "sort_nodes",
]
