"""The Evidence Relationship Graph Engine (Phase 8.2).

Pure, deterministic, offline. Every node and edge is derived from data
already present on a completed :class:`~threatlens.reasoning.models.InvestigationSummary`
and/or :class:`~threatlens.correlation.models.CorrelationSummary` — never
from the wall clock, never from AI, never from similarity or inference.

Two independent sources, one collection pass each:

* **Findings** (``InvestigationSummary.findings``): each finding's own
  ``subject_type``/``subject_value`` is a node — the finding itself is the
  evidence a Reasoning conclusion exists about that entity. Each
  :class:`~threatlens.providers.results.Relationship` the finding carries is
  an explicit, provider-reported edge to another entity.
* **Correlation observations** (``CorrelationSummary.observations``): each
  observation becomes its own node (a ``correlation_observation`` — a
  higher-level object the Correlation Engine already produced, not an
  invented one) connected via a graph-local ``correlated_with`` edge to
  every distinct entity its own ``evidence`` cites. Each explicit
  :class:`~threatlens.correlation.models.CorrelationRelationship` the
  observation carries additionally becomes a direct entity-to-entity edge,
  typed with the correlation engine's own relationship verb — except where
  both ends resolve to the same entity (a same-subject rule linking two
  findings on one subject), which is skipped as a self-loop that would add
  no connectivity beyond what the observation's own edges above already show.

Both passes key everything on content-addressed ids, so the exact same input
always produces the exact same set of nodes and edges — see
:func:`compute_node_id`/:func:`compute_edge_id` — and repeated citations of
the same node or edge accumulate onto one canonical element rather than
creating duplicates.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from pydantic import JsonValue

from ..correlation.models import CorrelationObservation, CorrelationSummary
from ..entities.types import EntityType
from ..reasoning.models import Finding, InvestigationSummary, Severity
from .models import GraphEdge, GraphNode

GRAPH_ENGINE_VERSION = "1.0"

# Graph-local vocabulary. Not one of the reused domain enums (EntityType,
# RelationshipTargetType, RelationshipType, CorrelationRelationshipType)
# because a CorrelationObservation is not itself an entity — it is a
# higher-level object the Correlation Engine already produces. Both values
# are exactly the "potential" labels the Phase 8.2 brief itself names for
# this purpose, never novel inventions.
OBSERVATION_NODE_TYPE = "correlation_observation"
CORRELATED_WITH = "correlated_with"


# --------------------------------------------------------------------------- #
# Identity (stable, content-addressed — never includes timestamps or evidence)
# --------------------------------------------------------------------------- #


def compute_node_id(*, node_type: str, value: str) -> str:
    """Content-addressed, deterministic node id.

    Hashes only ``node_type`` and the canonicalized ``value`` — never the
    current time, a random UUID, or list position — so the same canonical
    entity always produces the same id, and equivalent representations
    collapse into one node purely because they hash identically.
    """
    payload = "|".join([node_type, value.strip().lower()])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"node_{digest}"


def compute_edge_id(*, source_node_id: str, target_node_id: str, relationship_type: str) -> str:
    """Content-addressed, deterministic edge id.

    Hashes only the two canonical node ids and the relationship type —
    deliberately excluding evidence references — so the same relationship
    claim always produces the same edge id regardless of how many findings
    or correlation observations assert it; repeated assertions accumulate
    onto the one canonical edge (see :func:`collect_graph`) instead of
    minting duplicates.
    """
    payload = "|".join([source_node_id, target_node_id, relationship_type])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"edge_{digest}"


# --------------------------------------------------------------------------- #
# Ordering
# --------------------------------------------------------------------------- #


def sort_nodes(nodes: Iterable[GraphNode]) -> tuple[GraphNode, ...]:
    """Deterministic ordering: node type, then canonical value, then node id."""
    return tuple(sorted(nodes, key=lambda n: (n.node_type, n.value.strip().lower(), n.node_id)))


def sort_edges(edges: Iterable[GraphEdge]) -> tuple[GraphEdge, ...]:
    """Deterministic ordering: relationship type, source id, target id, then edge id."""
    return tuple(
        sorted(
            edges,
            key=lambda e: (e.relationship_type, e.source_node_id, e.target_node_id, e.edge_id),
        )
    )


# --------------------------------------------------------------------------- #
# Collection (accumulate-by-id, mirroring correlation/timeline's dedup style)
# --------------------------------------------------------------------------- #


@dataclass
class _NodeDraft:
    node_type: str
    label: str
    value: str
    metadata: dict[str, JsonValue] = field(default_factory=dict)
    severities: list[Severity] = field(default_factory=list)
    source_refs: set[str] = field(default_factory=set)


@dataclass
class _EdgeDraft:
    source_node_id: str
    target_node_id: str
    relationship_type: str
    explanation: str
    evidence_refs: set[str] = field(default_factory=set)
    source_refs: set[str] = field(default_factory=set)


def _record_node(
    drafts: dict[str, _NodeDraft],
    *,
    node_type: str,
    value: str,
    label: str | None,
    severity: Severity | None,
    source_ref: str,
    metadata: dict[str, JsonValue] | None = None,
) -> str:
    """Insert-or-accumulate the node for ``(node_type, value)``; return its id."""
    node_id = compute_node_id(node_type=node_type, value=value)
    draft = drafts.get(node_id)
    if draft is None:
        draft = _NodeDraft(
            node_type=node_type,
            label=label or value,
            value=value,
            metadata=metadata or {},
        )
        drafts[node_id] = draft
    if severity is not None:
        draft.severities.append(severity)
    draft.source_refs.add(source_ref)
    return node_id


def _record_edge(
    drafts: dict[str, _EdgeDraft],
    *,
    source_node_id: str,
    target_node_id: str,
    relationship_type: str,
    explanation: str,
    evidence_ref: str | None,
    source_ref: str,
) -> None:
    """Insert-or-accumulate the edge for ``(source, target, relationship_type)``."""
    edge_id = compute_edge_id(
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        relationship_type=relationship_type,
    )
    draft = drafts.get(edge_id)
    if draft is None:
        draft = _EdgeDraft(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship_type=relationship_type,
            explanation=explanation,
        )
        drafts[edge_id] = draft
    if evidence_ref is not None:
        draft.evidence_refs.add(evidence_ref)
    draft.source_refs.add(source_ref)


def _collect_from_findings(
    findings: Sequence[Finding],
    nodes: dict[str, _NodeDraft],
    edges: dict[str, _EdgeDraft],
) -> None:
    """Every finding's own subject is a node; every relationship it reports is an edge."""
    for finding in findings:
        subject_node_id = _record_node(
            nodes,
            node_type=finding.subject_type.value,
            value=finding.subject_value,
            label=None,
            severity=finding.severity,
            source_ref=finding.id,
        )
        for attributed in finding.relationships:
            rel = attributed.relationship
            target_node_id = _record_node(
                nodes,
                node_type=rel.target_type.value,
                value=rel.target_value,
                label=None,
                severity=None,
                source_ref=finding.id,
            )
            _record_edge(
                edges,
                source_node_id=subject_node_id,
                target_node_id=target_node_id,
                relationship_type=rel.relationship.value,
                explanation=rel.description or "",
                evidence_ref=finding.id,
                source_ref=finding.id,
            )


def _collect_from_observations(
    observations: Sequence[CorrelationObservation],
    nodes: dict[str, _NodeDraft],
    edges: dict[str, _EdgeDraft],
) -> None:
    """Each observation is a node; its cited entities and explicit relationships are edges."""
    for observation in observations:
        observation_node_id = _record_node(
            nodes,
            node_type=OBSERVATION_NODE_TYPE,
            value=observation.id,
            label=observation.title,
            severity=None,
            source_ref=observation.id,
            metadata={"rule_id": observation.rule_id, "category": observation.category.value},
        )

        finding_subjects: dict[str, tuple[EntityType, str]] = {}
        for evid in observation.evidence:
            finding_subjects[evid.finding_id] = (evid.subject_type, evid.subject_value)
            entity_node_id = _record_node(
                nodes,
                node_type=evid.subject_type.value,
                value=evid.subject_value,
                label=None,
                severity=None,
                source_ref=evid.finding_id,
            )
            _record_edge(
                edges,
                source_node_id=observation_node_id,
                target_node_id=entity_node_id,
                relationship_type=CORRELATED_WITH,
                explanation=observation.title,
                evidence_ref=evid.finding_id,
                source_ref=observation.id,
            )

        for rel in observation.relationships:
            # Guarded rather than asserted: nothing in the CorrelationRelationship
            # /CorrelationObservation *model* guarantees this cross-reference (only
            # today's engine implementation happens to always populate it), so an
            # absent subject is treated as unsupported and skipped, never invented.
            source_subject = finding_subjects.get(rel.source_finding_id)
            target_subject = finding_subjects.get(rel.target_finding_id)
            if source_subject is None or target_subject is None:
                continue

            source_node_id = compute_node_id(
                node_type=source_subject[0].value, value=source_subject[1]
            )
            target_node_id = compute_node_id(
                node_type=target_subject[0].value, value=target_subject[1]
            )
            if source_node_id == target_node_id:
                continue  # same-subject self-loop — see module docstring

            _record_edge(
                edges,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                relationship_type=rel.type.value,
                explanation=rel.description,
                evidence_ref=observation.id,
                source_ref=observation.id,
            )


def collect_graph(
    summary: InvestigationSummary | None,
    correlation: CorrelationSummary | None,
) -> tuple[tuple[GraphNode, ...], tuple[GraphEdge, ...]]:
    """Derive every graph node and edge from a saved investigation's existing outputs.

    Both inputs are read-only and independently optional: nothing here
    mutates a ``Finding`` or a ``CorrelationObservation``, and an investigation
    with neither (or with findings/observations that carry no relationships)
    deterministically produces an empty graph — not an error.
    """
    node_drafts: dict[str, _NodeDraft] = {}
    edge_drafts: dict[str, _EdgeDraft] = {}

    if summary is not None:
        _collect_from_findings(summary.findings, node_drafts, edge_drafts)
    if correlation is not None:
        _collect_from_observations(correlation.observations, node_drafts, edge_drafts)

    nodes = [
        GraphNode(
            node_id=node_id,
            node_type=draft.node_type,
            label=draft.label,
            value=draft.value,
            severity=max(draft.severities) if draft.severities else None,
            source_references=tuple(sorted(draft.source_refs)),
            metadata=draft.metadata,
        )
        for node_id, draft in node_drafts.items()
    ]
    edges = [
        GraphEdge(
            edge_id=edge_id,
            source_node_id=draft.source_node_id,
            target_node_id=draft.target_node_id,
            relationship_type=draft.relationship_type,
            explanation=draft.explanation,
            evidence_references=tuple(sorted(draft.evidence_refs)),
            source_references=tuple(sorted(draft.source_refs)),
        )
        for edge_id, draft in edge_drafts.items()
    ]
    return sort_nodes(nodes), sort_edges(edges)
