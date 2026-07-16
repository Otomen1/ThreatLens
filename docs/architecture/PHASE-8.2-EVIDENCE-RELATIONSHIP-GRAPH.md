# Phase 8.2 — Evidence Relationship Graph Framework

## Status

Complete. A pure, deterministic, **read-only** consumer of a saved
investigation's existing outputs. **Not a new intelligence engine** — it
derives a graph of entities and relationships only from evidence that
already explicitly supports them. It never invents an entity, never infers
a relationship, and never connects two entities merely because they
co-occur in the same investigation. No AI, no probabilistic similarity.

## Purpose

A saved `WorkspaceInvestigation` (Phase 8.0) bundles an
`InvestigationSummary` and, optionally, a `CorrelationSummary` — both rich
in explicit entity relationships (a finding's reported `Relationship` to
another entity; a correlation observation's cited findings and their
pairwise `CorrelationRelationship`), but nothing renders those connections
as a graph. Phase 8.2 answers that by reading the relationship data that
already exists and presenting it as nodes and edges — nothing more, nothing
invented. It is a sibling of Phase 8.1's Timeline: both are read-only
derived views over the same saved investigation, and neither depends on
the other.

## Architecture

`backend/src/threatlens/graph/`:

| Module | Role |
|---|---|
| `models.py` | `GraphNode`, `GraphEdge`, `EvidenceGraph` — frozen value objects. |
| `engine.py` | `compute_node_id`, `compute_edge_id`, `collect_graph`, `sort_nodes`, `sort_edges` — the pure derivation logic. No I/O, no wall clock. |
| `service.py` | `GraphService` — adapts a `WorkspaceInvestigation` into an `EvidenceGraph`. |

There is no `exceptions.py`, matching Timeline's own precedent: the graph
is always derivable (a saved investigation with neither
`investigation_summary` nor `correlation_summary` attached yields a
well-formed empty graph, not an error), so there is no failure mode of this
framework's own to name.

Data flow: `GET /api/v1/workspace/{id}/graph` → `WorkspaceService.get(id)`
(existing, unchanged — 404 if missing) → `GraphService.build(record)` →
`engine.collect_graph(record.investigation_summary, record.correlation_summary)`
→ `EvidenceGraph`. Nothing is written back to the saved record; nothing is
cached; every call recomputes from the same source, deterministically.

```
Workspace Investigation
        │
        ├── Timeline    (Phase 8.1 — evidence.observed_at)
        │
        └── Evidence Graph  (Phase 8.2 — relationships + correlation)
```

Both derive independently from the same saved record; neither is wired
through the other, per the brief's preference for sibling views.

## Graph model

```python
class GraphNode(BaseModel):             # frozen
    node_id: str                        # content-addressed
    node_type: str                      # verbatim value from an existing enum
    label: str                          # display name
    value: str                          # the canonical value identity was computed from
    severity: Severity | None            # worst-case across findings whose own subject this is
    source_references: tuple[str, ...]   # finding/observation ids that support this node
    metadata: dict[str, JsonValue]        # sparse; only populated for observation nodes

class GraphEdge(BaseModel):             # frozen
    edge_id: str                        # content-addressed
    source_node_id: str
    target_node_id: str
    relationship_type: str              # verbatim value from an existing enum
    explanation: str                    # human-readable description, copied verbatim
    evidence_references: tuple[str, ...]  # finding id(s) that specifically assert this edge
    source_references: tuple[str, ...]    # id(s) of the higher-level object the edge came from

class EvidenceGraph(BaseModel):         # frozen
    investigation_id: UUID
    entity_type: EntityType
    entity_value: str
    generated_at: datetime              # inherited, never datetime.now()
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    node_count: int                     # = len(nodes), set once at construction
    edge_count: int                     # = len(edges), set once at construction
    graph_version: str
```

`severity` reuses `threatlens.reasoning.models.Severity`; `entity_type`
reuses `threatlens.entities.types.EntityType`. Neither is redeclared.

`node_type`/`relationship_type` are plain `str` rather than one shared
enum, by design: the underlying vocabularies genuinely differ by source —
`EntityType` for a finding's own subject, `RelationshipTargetType` for a
relationship's target, `RelationshipType` for a finding-level relationship
verb, `CorrelationRelationshipType` for a correlation-level relationship
verb. Forcing all four into one Pydantic enum field would either lose
information (the vocabularies are deliberately not identical — see
"Canonicalization") or produce ambiguous validation where two enums share a
string value. Every value stored is still drawn **verbatim** from one of
those existing closed vocabularies (plus two graph-local constants —
`correlation_observation` and `correlated_with` — both literally the
"potential" labels this phase's own brief names for this purpose, never
novel inventions).

## Supported node types

Derived only from what the two existing engines already produce:

- **A finding's own subject** (`Finding.subject_type`/`subject_value`) — the
  Reasoning Engine's own conclusion that this entity matters; a node whose
  `node_type` is one of the existing `EntityType` values (`ipv4`, `domain`,
  `malware_family`, `threat_actor`, `mitre_technique`, …).
- **A relationship's target** (`Relationship.target_type`/`target_value` on
  an `AttributedRelationship`) — a node whose `node_type` is one of the
  existing `RelationshipTargetType` values (`malware_family`,
  `threat_actor`, `campaign`, `vulnerability`, `weakness`,
  `attack_pattern`, `infrastructure`, `tool`, `report`, `indicator`).
- **A correlation observation** (`CorrelationObservation`) — a node typed
  `correlation_observation`, representing the higher-level object the
  Correlation Engine already produced (not an entity, and not invented by
  this phase).

No "finding" node type exists: a `Finding` has no graph identity distinct
from its own subject entity, and its provenance is already fully carried by
the subject node's `source_references` — adding a separate node per finding
would inflate node count without adding connectivity, contrary to "quality
over node count."

## Supported edge types

Reused verbatim from the two existing relationship vocabularies, plus one
graph-local structural label:

- **Finding-level** (`RelationshipType`): `resolves_to`, `communicates_with`,
  `associated_with`, `attributed_to`, `exploits`, `uses`, `related_to`,
  `downloaded_from`, `drops`, `part_of`, `variant_of`, `indicates`,
  `referenced_in` — whichever verb the reporting provider actually recorded
  on a `Relationship`.
- **Correlation-level** (`CorrelationRelationshipType`): `co_occurs_with`,
  `exposes`, `associated_with`, `mapped_to`, `attributed_to`, `exploits` —
  the exact verb the correlation rule that fired already assigned.
- **`correlated_with`** (graph-local): the structural edge from a
  `correlation_observation` node to every distinct entity its own evidence
  cites. Not a semantic claim about the entities themselves — it documents
  how the observation was constructed, exactly as
  `CorrelationObservation.source_finding_ids` already does.

No edge type is invented beyond these; no causality is asserted by any of
them (`co_occurs_with`, not `causes`).

## Correlation integration

`CorrelationSummary` is read in full, never modified — nothing here touches
`correlation/engine.py`, `correlation/registry.py`, the rule library, the
models, or the service. Two things are reused per observation:

1. **`CorrelationObservation.evidence`** (a tuple of `CorrelationEvidence`,
   each already carrying `finding_id`/`subject_type`/`subject_value`) — used
   directly to build the observation's hub edges to every distinct cited
   entity. This is fully self-contained: no cross-reference back into
   `InvestigationSummary.findings` is needed, since `CorrelationEvidence`
   already copies the subject fields at correlation time.
2. **`CorrelationObservation.relationships`** (a tuple of
   `CorrelationRelationship`, each naming a `source_finding_id`/
   `target_finding_id` pair and a specific `CorrelationRelationshipType`) —
   resolved to the two entities via the same observation's own `evidence`
   (a local `finding_id → (subject_type, subject_value)` map), then
   rendered as a **direct** entity-to-entity edge typed with the
   correlation engine's own verb — richer than the generic
   `correlated_with` hub edge, and only drawn when the two ends resolve to
   *different* entities (see "Known limitations" on same-subject
   self-loops).

If a `CorrelationRelationship`'s finding id isn't present among the
observation's own evidence — nothing in the model *guarantees* this cross
reference, even though today's correlation engine always populates it
consistently — the edge is silently skipped rather than guessed at
(`test_engine.py::test_relationship_referencing_an_unknown_finding_is_skipped`).

## Node identity

```python
def compute_node_id(*, node_type: str, value: str) -> str:
    payload = "|".join([node_type, value.strip().lower()])
    return f"node_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"
```

Hashes only `node_type` and the canonicalized `value` — never the current
time, `generated_at`, a random UUID, or list position — so the same
canonical entity always produces the same node, regardless of how many
findings or relationships cite it, or in what order. For a correlation
observation node, `value` is the observation's own `id` — already
content-addressed and stable, so reusing it verbatim as the hash input
requires no extra assumptions.

## Edge identity

```python
def compute_edge_id(*, source_node_id: str, target_node_id: str, relationship_type: str) -> str:
    payload = "|".join([source_node_id, target_node_id, relationship_type])
    return f"edge_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"
```

Hashes the two canonical node ids and the relationship type — deliberately
**excluding** evidence references. The brief allows "stable supporting
evidence references where required"; nothing in this framework's edge
model requires them for uniqueness — two assertions of the same
`(source, target, relationship_type)` triple are, semantically, the same
relationship claim regardless of who asserted it, so folding evidence into
the hash would only ever fragment one true edge into several. Repeated
assertions instead accumulate onto the one canonical edge's
`evidence_references` (see "Deduplication").

## Canonicalization

Existing normalization was inspected before implementation (`entities/models.py`'s
`Entity.value`/`normalized_value`, `providers/aggregation.py`'s
`.strip().lower()` identity idiom, `timeline/engine.py`'s identical
pattern) — no second, competing normalization system is introduced. Node
identity reuses exactly that idiom: `value.strip().lower()`.

Two source vocabularies for `node_type` — `EntityType` (a finding's own
subject) and `RelationshipTargetType` (a relationship's target) — are
**not** unified by any explicit remapping table. Where they happen to share
an identical string value (`malware_family`, `threat_actor` appear
verbatim in both enums — a deliberate alignment, per
`providers/results.py`'s own docstring), the *same* canonicalized
`(node_type, value)` pair falls out automatically, and the two occurrences
collapse into one node with no special-case code
(`test_engine.py::TestCanonicalization::test_shared_string_value_across_entitytype_and_relationshiptargettype_collapses`).
Where the vocabularies deliberately diverge (`RelationshipTargetType.VULNERABILITY`
= `"vulnerability"` vs. `EntityType.CVE` = `"cve"`), they remain distinct
nodes — the brief's "do not perform speculative entity resolution" is
honored by simply never attempting a cross-vocabulary mapping, not by a
heuristic that might get it wrong.

## Deduplication

Both nodes and edges are accumulated into a dict keyed by their
content-addressed id before the final `EvidenceGraph` is built (mirroring
`timeline.engine.collect_events`'s and
`correlation/aggregation.py`'s existing "group-then-finalize" idiom):

- **Nodes**: the same canonical entity, however many findings or
  relationships reference it, produces exactly one `GraphNode`.
  `source_references` accumulates every citing finding/observation id
  (deduplicated, sorted); `severity` takes the worst case across every
  finding whose *own subject* — never a mere relationship target — is this
  entity.
- **Edges**: the same `(source, target, relationship_type)` triple,
  however many findings or correlation observations assert it, produces
  exactly one `GraphEdge`. `evidence_references`/`source_references`
  accumulate across every asserting source.

Genuinely distinct entities are never merged solely because their labels
look similar — identity is always the exact canonicalized value, never a
fuzzy or partial match.

## Ordering

```python
sort_nodes: key = (node_type, value.strip().lower(), node_id)
sort_edges: key = (relationship_type, source_node_id, target_node_id, edge_id)
```

Every field is a plain, total-order-comparable string, so both sorts are
fully deterministic regardless of collection order — proven directly by
`test_reordering_input_findings_does_not_change_output` (swapping input
finding order produces a byte-identical graph) and
`test_sort_functions_are_pure_and_repeatable` (sorting an already-sorted or
reversed sequence yields the same result). Ties are broken, in order, by
each key's next field, down to the always-unique content-addressed id.

## Workspace integration

`GET /api/v1/workspace/{investigation_id}/graph` — added to the existing
`api/routes/workspace.py` router (a sub-resource of a saved investigation,
exactly like the Phase 8.1 timeline route). Loads the record via the
unmodified `WorkspaceService.get()` (404 via the existing
`InvestigationNotFoundError` → `HTTPException`), then hands it to
`GraphService.build()`. **Every existing workspace endpoint** —
`POST`/`GET`/`GET {id}`/`PUT {id}`/`DELETE {id}`/`GET {id}/timeline` — **is
unchanged**; this is a pure addition. No new field was added to
`WorkspaceInvestigation`: per the brief's preference, the graph is always
derived, never duplicated into persisted storage.

## Frontend

- **`frontend/lib/api/workspace.ts`** gained `GraphNode`/`GraphEdge`/
  `EvidenceGraph` types and `getInvestigationGraph(id, signal)`.
  `node_type`/`relationship_type` are left as plain `string` (mirroring
  `TimelineEvent.event_type`'s own treatment, for the same reason: the
  underlying vocabularies genuinely differ by source and nothing in the UI
  branches on a specific value).
- **`frontend/app/workspace/[id]/page.tsx`** gained one new section,
  `GraphSection` — collapsed by default, fetched lazily on first expand,
  mirroring `TimelineSection`'s disclosure pattern exactly (same
  loading/failed/empty/data states, same shared `Chevron` component),
  rendered as a sibling directly below the Timeline section. Nodes and
  edges are rendered as plain lists — a node-type badge, label, and
  severity badge per node; a source-label / relationship-type badge /
  target-label row plus its explanation per edge — with edge endpoints
  resolved to node labels for readability. Clicking a node toggles a small
  inline detail panel showing its `source_references` and `metadata`
  ("basic node inspection," per the brief). No graph-visualization library,
  no drag-to-create, no AI suggestions, no inferred edges; the section
  never re-lays-out, re-infers, or re-derives what the backend returns.

## Testing

`backend/tests/graph/` (91 tests):

- **`test_models.py`** — the node/edge/graph envelope: frozen, defaults,
  validation, JSON round-tripping.
- **`test_engine.py`** — finding-derived nodes/edges, canonicalization
  (vocabulary alignment across `EntityType`/`RelationshipTargetType`, and
  proof that genuinely distinct vocabularies are never speculatively
  merged), deduplication (identical relationships across findings, shared
  subjects), correlation-derived nodes/edges (single- and multi-entity
  hubs, direct typed edges, same-subject self-loop omission, defensive
  skip of an unresolvable relationship, cross-observation node sharing),
  `compute_node_id`/`compute_edge_id` determinism, `sort_nodes`/`sort_edges`
  ordering including input-order independence, and read-only behavior (both
  the source `InvestigationSummary` and `CorrelationSummary` are provably
  unchanged after derivation).
- **`test_service.py`** — the `WorkspaceInvestigation` adaptation,
  including the no-attached-summary fallback, the with-summary path, and
  correlation-without-a-summary (a state the model technically permits).
- **`test_api.py`** — the full HTTP contract: `200`/`404`/`422`, response
  shape, the empty-graph case, a real `/investigate` summary round-tripped
  through save → graph, repeated-fetch byte-identity, that the saved
  record is never mutated, and that the sibling timeline route still works
  alongside the new graph route.
- **`test_no_regression.py`** — every pre-Phase-8.2 route (via the OpenAPI
  schema, including the Phase 8.1 timeline route), every existing
  workspace/timeline operation's HTTP methods, and every engine version
  constant (Reasoning, Detection, Correlation, Timeline), all unchanged;
  the new graph route is purely additive.
- **`test_golden.py`** + **`corpus.py`** (15 scenarios, `golden.json`) — a
  focused golden regression (`THREATLENS_UPDATE_GOLDEN=1` to regenerate,
  matching Timeline's and Correlation's exact mechanism) covering every
  documented policy decision: empty investigation, a finding with no
  relationships, a single relationship edge, a duplicated relationship
  across findings, vocabulary alignment (and non-alignment), single- and
  multi-entity correlation hubs, same-subject self-loop omission,
  unresolvable-relationship skip, cross-observation node sharing, severity
  aggregation, the referenced-but-never-a-subject no-severity rule, an
  empty observation list, and a relationship with no description.

Frontend: 5 new tests in `frontend/lib/api.test.ts` (this codebase's
established single file for the whole `lib/api/` barrel). The new UI was
verified with a real, scripted Playwright browser session against a live
backend: a hand-built investigation with two findings sharing one subject
(a malicious, exposed IP), a relationship to a malware family and to a
related infrastructure IP, and a correlation observation over the two
findings correctly produced 4 nodes and 3 edges — the observation hub, the
malware/infrastructure targets, the shared subject with its worst-case
severity, correct relationship-type labels, **no self-loop edge** for the
same-subject correlation relationship, and working node inspection
(clicking the subject node revealed its two source finding ids); a bare
investigation with no attached results correctly showed the "no
evidence-supported entities" empty state.

Full suite after this phase: **2,668 backend tests passed, 1 skipped** (was
2,577). Ruff and mypy (`--strict`) clean across 186 source files (was 182).
Frontend: 132 Vitest tests passed (was 127); production build clean,
including the graph section on the existing `/workspace/[id]` route (no
new route — the endpoint is a sub-resource, not a page).

## Known limitations

- **Self-referential correlation relationships are not rendered as
  self-loops.** A same-subject correlation rule (e.g. "malicious and
  exposed on the same IP") produces a `CorrelationRelationship` between two
  findings that share one subject; resolving both ends to that one entity
  would be a self-loop conveying no connectivity beyond what the entity
  node's own multiplicity and the observation's hub edge already show, so
  it is omitted. The underlying evidence is not lost — it is fully
  represented via the observation node and its `correlated_with` edge to
  that single entity.
- **`Relationship.confidence`/no per-edge confidence is surfaced.** The
  source models carry a confidence score on some relationships; this phase
  does not propagate it onto `GraphEdge`, matching the brief's suggested
  field list. A future phase could add it without changing edge identity.
- **No "finding" node type**, by design — see "Supported node types."
- **No cross-investigation graph.** Each `EvidenceGraph` is scoped to
  exactly one saved investigation; there is no merged view across multiple
  saved cases in this phase.
- **No persistence of graph data.** Per the brief's preference,
  `WorkspaceInvestigation` gains no new field — an `EvidenceGraph` is
  always recomputed from the saved record's existing
  `investigation_summary`/`correlation_summary`, never stored.
- **No pagination, no graph-visualization layout.** Acceptable at the
  intended scale (one saved investigation's own evidence); the frontend
  renders plain lists, not a node-link diagram, per the brief's "simplest
  implementation that clearly communicates relationships."

## Future extensions (explicitly out of scope for this phase)

Per the brief: Analyst Notes, Audit History, Export/Reporting,
Authentication, RBAC, database migration, STIX/TAXII, SOAR, and any other
future phase are not started. Natural next steps this phase's design
already accommodates without rework: a real node-link visual layout reusing
the existing `GraphNode`/`GraphEdge` shape verbatim; per-edge confidence;
a cross-investigation merged graph; export formats (e.g. STIX SRO/SDO,
already hinted at by `RelationshipTargetType`'s STIX-aligned vocabulary).

## Readiness review

**GO.**

- No engine changes: Reasoning, Detection, Correlation, Exposure, Identity,
  and Timeline are byte-for-byte unmodified (engine version constants
  unchanged; verified by `test_no_regression.py`).
- No existing API changes: every pre-Phase-8.2 workspace/timeline operation
  keeps its exact HTTP methods and response shape; the new graph route is
  purely additive.
- No AI, no invented entities, no invented relationships, no inferred
  causality — every node/edge traces to an explicit `Relationship`,
  `Finding.subject`, or `CorrelationObservation`/`CorrelationRelationship`
  already produced by an existing engine.
- Stable ids (`compute_node_id`/`compute_edge_id`, content-addressed) and
  stable ordering (`sort_nodes`/`sort_edges`, deterministic tiebreak), both
  proven by repeated runs, input-order shuffling, and the golden corpus.
- Existing tests: full backend suite green, **2,668 passed / 1 skipped**
  (up from 2,577 — the delta is entirely new graph + regression tests).
  Frontend: 132 Vitest tests passed (up from 127), production build clean.
- Manually verified end-to-end in a real browser against a live backend
  with hand-built, realistic evidence and a real correlation observation:
  correct node/edge counts, correct relationship labels, correct
  same-subject self-loop omission, correct worst-case severity, working
  node inspection, and the correct empty state for an investigation with no
  attached results.
