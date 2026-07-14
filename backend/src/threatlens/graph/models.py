"""Canonical models for the Evidence Relationship Graph Framework (Phase 8.2).

A pure, deterministic, **read-only** consumer of a saved investigation's
already-computed :class:`~threatlens.reasoning.models.InvestigationSummary`
and :class:`~threatlens.correlation.models.CorrelationSummary`. It derives a
graph of entities and their explicit relationships — it never invents an
entity, never infers a relationship, and never connects two entities merely
because they co-occur in the same investigation. No AI, no probabilistic
similarity, no new intelligence engine.

``node_type``/``relationship_type`` are plain ``str`` rather than one shared
enum: the underlying vocabularies genuinely differ by source —
:class:`~threatlens.entities.types.EntityType` for a finding's own subject,
:class:`~threatlens.providers.results.RelationshipTargetType` for a
relationship's target, :class:`~threatlens.providers.results.RelationshipType`
for a finding-level relationship verb,
:class:`~threatlens.correlation.models.CorrelationRelationshipType` for a
correlation-level relationship verb — and forcing them into one Pydantic enum
field would either lose information or require the kind of speculative
remapping this framework's canonicalization policy explicitly forbids. Every
value stored is still drawn verbatim from one of those existing closed
vocabularies (plus two graph-local constants documented in ``engine.py``) —
never invented. See the architecture doc's "Node identity"/"Edge identity".
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ..entities.types import EntityType
from ..reasoning.models import Severity

GRAPH_FRAMEWORK_VERSION = "1.0"


class GraphNode(BaseModel):
    """One entity or correlation observation supported by existing evidence.

    ``node_id`` is content-addressed (see ``engine.compute_node_id``): it
    hashes only ``node_type`` and the canonicalized ``value`` — never a
    generation-time value, a random UUID, or list position — so the same
    underlying entity always produces the same node, and equivalent
    representations collapse into one node purely because they hash
    identically.

    ``severity`` is the worst (highest) severity among every finding whose
    *own subject* is this entity — never recomputed, and left ``None`` for
    an entity that is only ever referenced as a relationship target or is a
    correlation observation (neither carries a severity of its own; see the
    architecture doc's "Known limitations" for why none is inferred).
    """

    model_config = ConfigDict(frozen=True)

    node_id: str = Field(min_length=1)
    node_type: str = Field(min_length=1)
    label: str = Field(min_length=1)
    value: str = Field(min_length=1)
    severity: Severity | None = None
    source_references: tuple[str, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """One explicit, evidence-supported relationship between two graph nodes.

    ``edge_id`` is content-addressed from ``source_node_id``,
    ``target_node_id``, and ``relationship_type`` only — deliberately
    excluding evidence references — so the same relationship claim always
    produces the same edge id regardless of how many findings or correlation
    observations assert it; repeated assertions accumulate onto the one
    canonical edge's ``evidence_references`` instead of minting duplicates.

    ``evidence_references`` are the finding id(s) whose content directly
    asserts this relationship. ``source_references`` are the id(s) of the
    higher-level engine output the edge was derived from (a
    :class:`~threatlens.reasoning.models.Finding` id for a finding-level
    relationship, a :class:`~threatlens.correlation.models.CorrelationObservation`
    id for a correlation-level one). For a finding-level edge these two sets
    are typically identical (the finding is both); for a correlation-level
    edge they differ (specific citing findings vs. the observation as a
    whole) — both are kept because they answer different questions.
    """

    model_config = ConfigDict(frozen=True)

    edge_id: str = Field(min_length=1)
    source_node_id: str = Field(min_length=1)
    target_node_id: str = Field(min_length=1)
    relationship_type: str = Field(min_length=1)
    explanation: str = ""
    evidence_references: tuple[str, ...] = ()
    source_references: tuple[str, ...] = ()


class EvidenceGraph(BaseModel):
    """Every node and edge derived from one saved investigation, ordered deterministically.

    ``generated_at`` is inherited from the source
    ``InvestigationSummary.generated_at`` (or, when no summary is attached,
    the saved record's own ``updated_at``) — never the wall clock — mirroring
    :class:`~threatlens.timeline.models.Timeline` exactly, so building a graph
    twice from the same saved investigation yields a byte-identical
    ``EvidenceGraph``.

    ``node_count``/``edge_count`` are stored rather than computed on read,
    but :class:`~threatlens.graph.service.GraphService` is the only place an
    ``EvidenceGraph`` is ever built, and it always sets them from
    ``len(nodes)``/``len(edges)`` — the same "explicit, not defaulted"
    treatment as ``graph_version`` — so they can never diverge from the
    tuples they describe.
    """

    model_config = ConfigDict(frozen=True)

    investigation_id: UUID
    entity_type: EntityType
    entity_value: str
    generated_at: datetime
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    graph_version: str = Field(min_length=1)

    @property
    def is_empty(self) -> bool:
        """True when no evidence-supported node was derived."""
        return not self.nodes
