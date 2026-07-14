"""The Evidence Relationship Graph service (Phase 8.2).

Adapts a saved :class:`~threatlens.workspace.models.WorkspaceInvestigation`
into an :class:`~threatlens.graph.models.EvidenceGraph`. All derivation logic
lives in :mod:`~threatlens.graph.engine`; this module owns only "which field
of a saved record feeds the graph" — no investigation logic, no reasoning, no
correlation, no persistence, no mutation of the saved record. A sibling of
:class:`~threatlens.timeline.service.TimelineService` — both derive from the
same saved record independently; neither depends on the other's output.
"""

from __future__ import annotations

from ..workspace.models import WorkspaceInvestigation
from .engine import collect_graph
from .models import GRAPH_FRAMEWORK_VERSION, EvidenceGraph


class GraphService:
    """Derives a read-only :class:`EvidenceGraph` from one saved investigation."""

    def build(self, record: WorkspaceInvestigation) -> EvidenceGraph:
        """Build the evidence graph for ``record``.

        Consumes ``record.investigation_summary`` and
        ``record.correlation_summary`` independently — either or both may be
        absent, in which case the result is a well-formed, empty graph (not
        an error), using the record's own ``investigation_type``/``updated_at``
        for context exactly like :class:`~threatlens.timeline.service.TimelineService`.
        """
        summary = record.investigation_summary
        correlation = record.correlation_summary

        if summary is None:
            entity_type = record.investigation_type
            entity_value = ""
            generated_at = record.updated_at
        else:
            entity_type = summary.entity_type
            entity_value = summary.entity_value
            generated_at = summary.generated_at

        nodes, edges = collect_graph(summary, correlation)
        return EvidenceGraph(
            investigation_id=record.id,
            entity_type=entity_type,
            entity_value=entity_value,
            generated_at=generated_at,
            nodes=nodes,
            edges=edges,
            node_count=len(nodes),
            edge_count=len(edges),
            graph_version=GRAPH_FRAMEWORK_VERSION,
        )
