# Phase 8.5 — Workspace Platform Stabilization & Freeze

## Status

Complete. **Not a feature phase.** Phase 8.5 makes no behavioral change to
Workspace, Timeline, Evidence Graph, Report, or Export — it documents and
freezes the contracts Phases 8.0–8.4 already built, verifies backward
compatibility across the realistic shapes a saved record can have, measures
a performance baseline, and confirms no analytical logic is duplicated
across the four subsystems. One documentation inaccuracy aside (Phase 8.4's
review already corrected the one that existed), every change in this phase
is either a new test or a new doc — never an application-code behavior
change. This document is the platform's canonical reference from this point
forward; it supersedes no phase document below it, but consolidates what
they each froze into one place.

## Purpose

Phases 8.0 through 8.4 shipped, in sequence: a persistence layer
(**Workspace**), two independent read-only derived projections
(**Timeline**, **Evidence Graph**), an interactive frontend for the graph,
and a composition of all of it into one export/report contract
(**Report**/**Export**). Each phase's own architecture document freezes that
phase's own contract in isolation. Phase 8.5 exists because a platform this
size needs one place that states, across all five pieces at once: exactly
which fields are guaranteed, what "backward compatible" means for a saved
record from an earlier phase, what the measured performance baseline is,
and what a future phase is and is not allowed to change without breaking
this freeze.

## Scope

**In scope:** `backend/src/threatlens/workspace/`, `reporting/`,
`timeline/`, `graph/`, `api/routes/workspace.py`, their models and tests,
the Workspace-related frontend (workspace list/detail/report pages and
components), and this documentation.

**Explicitly out of scope, unchanged by this phase:** Investigation
Intelligence (Reasoning), Detection Engineering, the Detection Knowledge
Library, Exposure Intelligence, Identity Intelligence, Correlation's own
engine/rule library, any provider integration, and the Operational
Dashboard. None of those subsystems' code was read for behavioral change
in this phase — only as the frozen, upstream producers of the data
Workspace persists verbatim.

## Component relationships

```
                    ┌─────────────────────────────────────────┐
                    │      Upstream engines (frozen, unchanged) │
                    │  Reasoning · Detection · Correlation      │
                    └───────────────────┬───────────────────────┘
                                        │ produces (verbatim, on request)
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │   WorkspaceInvestigation (mutable record) │
                    │   backend/src/threatlens/workspace/       │
                    │   LocalFileStorage — one JSON file/record │
                    └───────┬───────────────┬──────────────┬────┘
                            │               │              │
                            ▼               ▼              │
                 TimelineService   GraphService             │
                 (timeline/)       (graph/)                  │
                            │               │              │
                            └───────┬───────┘              │
                                    ▼                       │
                            ReportService (reporting/)◄─────┘
                          composes Timeline + Graph +
                          the record itself, verbatim
                                    │
                                    ▼
                     InvestigationReport (frozen envelope)
                     — backs GET .../export AND /workspace/{id}/report
```

Every arrow above is a **read-only, one-way** dependency. Timeline and
Graph are siblings: both consume `WorkspaceInvestigation` independently and
neither depends on the other. Report is the only one of the four services
that depends on siblings — it composes `TimelineService` and
`GraphService`'s own output rather than re-deriving either. No subsystem
below the top box ever writes back to an upstream engine, and nothing in
this stack ever calls an AI model, a network source, or an external
provider — every projection is a pure function of one already-persisted
`WorkspaceInvestigation`.

## Lifecycle

1. **Produce.** `/investigate`, `/detections`, and (once a later phase
   wires it in) correlation each produce a frozen output
   (`InvestigationSummary`, `DetectionPackage`, `CorrelationSummary`).
   Nothing in this lifecycle recomputes any of them.
2. **Save.** `POST /api/v1/workspace` attaches whichever of those outputs
   the caller already has (all three are optional) to a new
   `WorkspaceInvestigation`, assigns a fresh `uuid4()` id and
   `created_at`/`updated_at`, and persists it as one JSON file.
3. **Read / Update / Delete.** `GET`/`PUT`/`DELETE
   /api/v1/workspace/{id}` and `GET /api/v1/workspace` (list, with
   status/severity/type/tag/text filters) operate on that record. `PUT` is
   a partial update — an omitted field keeps its current value; only
   fields explicitly present in the request body change, including an
   explicit `null`.
4. **Project.** `GET .../timeline` and `GET .../graph` derive a
   `Timeline`/`EvidenceGraph` from whatever is currently attached to the
   record, on every call — never cached, never persisted, always
   recomputed from the record's current state.
5. **Compose.** `GET .../export` builds an `InvestigationReport`: the
   record verbatim plus the exact same `Timeline`/`EvidenceGraph` the
   routes above would return for that record right now. This one response
   backs both the raw JSON download and the `/workspace/{id}/report`
   analyst view — one contract, two presentations, per Phase 8.4.
6. **Present.** The frontend workspace list/detail pages render the record
   and its projections interactively (React Flow graph, collapsible
   sections); the report page renders the same data fully expanded for
   print. Neither page computes anything the backend didn't already
   compute.

## Evidence flow

Every fact that ends up in a `Timeline` event or an `EvidenceGraph`
node/edge originates from one of exactly two places already inside the
saved record:

- **`investigation_summary.findings[].evidence`** — each finding's cited
  evidence, itself an `AttributedEvidence` wrapping the Reasoning Engine's
  `Evidence` (which carries the optional `observed_at` timestamp Timeline
  requires) and the finding's own `subject_type`/`subject_value` (which
  Graph turns into a node) and `relationships` (which Graph turns into
  edges).
- **`correlation_summary.observations[]`** — each observation's cited
  entities and `CorrelationRelationship`s, which Graph turns into
  observation nodes and hub/relationship edges. Correlation carries no
  per-item evidence timestamp, so it contributes nothing to Timeline (see
  Known Limitations).

Nothing downstream of these two fields is ever consulted for event/node/edge
*content* — `detection_package` flows through the Report envelope verbatim
(so it survives in the JSON export and renders in the report's Detection
Outputs section) but is never read by Timeline or Graph derivation, and the
Phase 8.5 compatibility matrix (`tests/reporting/test_compatibility_matrix.py`)
explicitly proves its presence or absence never changes Timeline/Graph
output.

## Projection architecture

Timeline, Graph, and Report share one shape by convention, not by a shared
base class — there was never a need for one:

```python
class XService:
    def build(self, record: WorkspaceInvestigation) -> XModel: ...
```

Each `build()` is a pure function: same input, same output, every time,
with no hidden state, no I/O, no clock read, and no mutation of `record`.
`ReportService.build()` is the one exception to "no dependencies" — it
takes a `TimelineService` and a `GraphService` in its constructor and calls
their `build()` rather than importing `timeline/engine.py` or
`graph/engine.py` directly. This is the whole of the "reporting" package's
own logic: composition, nothing else. See `backend/src/threatlens/reporting/service.py`.

## Frozen contracts

The following are frozen as of this phase. **Do not change any of these
without an actual correctness bug** — additive, backward-compatible changes
(a new optional field, a new endpoint) are fine; anything else is a
breaking change and needs a version bump and a migration note, not a silent
edit.

### `WorkspaceInvestigation` (`workspace/models.py`)

The one model in this codebase that is **not frozen** (`model_config` is
the default, mutable Pydantic v2 behavior) — deliberately, since it is
mutated over its lifetime (status, tags, title, summary, severity, and
re-attaching a later-generated output all go through `PUT`).

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `uuid4()`, assigned once at save time. Random, **not** content-addressed — identical content saved twice yields two distinct records. |
| `title` | yes | 1–200 chars. |
| `created_at` | yes | Set once at save time; never changes on update. |
| `updated_at` | yes | Set at save time; bumped on every successful `PUT`. |
| `status` | yes (defaulted) | `WorkspaceStatus`: `open` \| `in_progress` \| `closed` \| `archived`. Default `open`. Analyst-controlled, never inferred. |
| `tags` | yes (defaulted `[]`) | Free-form strings. |
| `summary` | no | Max 2000 chars. |
| `severity` | no | `Severity` enum, shared with Reasoning. |
| `investigation_type` | yes | `EntityType`. |
| `investigation_summary` | no | The Reasoning Engine's frozen `InvestigationSummary`, attached verbatim. |
| `detection_package` | no | The Detection Engine's frozen `DetectionPackage`, attached verbatim. |
| `correlation_summary` | no | The Correlation Engine's frozen `CorrelationSummary`, attached verbatim. |

**Compatibility guarantee:** every one of the three nested engine outputs
is independently optional. A record with none, some, or all three attached
is valid and has been valid since Phase 8.0 — this was never a special case
added later, it is the original design.

### `Timeline` / `TimelineEvent` (`timeline/models.py`, frozen)

| `Timeline` field | Required | Notes |
|---|---|---|
| `investigation_id` | yes | Matches the source record's `id`. |
| `entity_type` / `entity_value` | yes | From `investigation_summary` when attached; `record.investigation_type`/`""` otherwise. |
| `generated_at` | yes | From `investigation_summary.generated_at` when attached; `record.updated_at` otherwise. **Never the wall clock.** |
| `events` | yes (defaulted `()`) | See ordering below. Empty is valid, not an error. |

`TimelineEvent.event_id` is **content-addressed**: hashed from event type,
subject, timestamp, summary, and value only — never a random id, never
generation time, never list position. Two evidence items with identical
content always produce the same event id, which is also the mechanism that
collapses duplicate evidence cited by more than one finding into one
canonical event (`source_id` = lexicographically smallest citing finding
id; `evidence_references` = every citing finding id, sorted; `severity` =
the worst of the citing findings').

**Ordering guarantee:** ascending by `timestamp`; ties broken by
`event_type`, then `event_id`. Deterministic regardless of input order.

**Identity guarantee:** rebuilding a `Timeline` from an unchanged record is
byte-identical, every time, forever — no field on this model is
non-deterministic.

### `EvidenceGraph` / `GraphNode` / `GraphEdge` (`graph/models.py`, frozen)

| `EvidenceGraph` field | Required | Notes |
|---|---|---|
| `investigation_id`, `entity_type`, `entity_value`, `generated_at` | yes | Same rules as `Timeline`, computed independently. |
| `nodes` / `edges` | yes (defaulted `()`) | See ordering below. |
| `node_count` / `edge_count` | yes | Always exactly `len(nodes)`/`len(edges)` — set by `GraphService`, never independently defaulted, can never diverge from the tuples. |
| `graph_version` | yes | Currently `"1.0"` (`GRAPH_FRAMEWORK_VERSION`). Bump this, not the shape, if the contract ever changes. |

`GraphNode.node_id` is content-addressed from `node_type` + canonicalized
`value` (case/whitespace-insensitive) — equivalent representations collapse
into one node. `GraphEdge.edge_id` is content-addressed from
`source_node_id` + `target_node_id` + `relationship_type` **only**,
deliberately excluding evidence references, so repeated assertions of the
same relationship accumulate onto one edge's `evidence_references` instead
of minting duplicates.

**Ordering guarantee:** nodes by `node_type`, then `value`, then `node_id`;
edges by `relationship_type`, then `source_node_id`, then `target_node_id`.
Deterministic regardless of input order.

**Asymmetry with `Timeline`, noted not fixed:** `EvidenceGraph` carries an
explicit `graph_version` field; `Timeline` does not carry an equivalent
field of its own (only the package-level `TIMELINE_FRAMEWORK_VERSION`
constant, not serialized onto the model). This predates Phase 8.5, is not
a correctness bug, and is left exactly as-is per this phase's "no schema
changes without an actual bug" rule — a future schema revision, if ever
needed, could add one additively.

### `InvestigationReport` (`reporting/models.py`, frozen)

| Field | Required | Notes |
|---|---|---|
| `report_schema_version` | yes | Currently `"1.0"` (`REPORTING_FRAMEWORK_VERSION`). Versions **only this envelope's own shape** — independent of `graph_version`/the timeline framework version nested inside it. |
| `investigation` | yes | The saved `WorkspaceInvestigation`, verbatim — identical to what `GET /workspace/{id}` returns for the same id. |
| `timeline` | yes | Identical to what `GET /workspace/{id}/timeline` returns for the same id, at the same moment. |
| `graph` | yes | Identical to what `GET /workspace/{id}/graph` returns for the same id, at the same moment. |

**No `exported_at` or any other wall-clock field exists on this model, by
design** — an export timestamp would only ever be request metadata, never
part of the report's semantic identity. This is what makes "repeated fetch
is byte-identical" a real, tested guarantee rather than an approximation.

**Compatibility guarantee:** every field on `investigation` is exactly as
optional here as on the plain record; `timeline.is_empty`/`graph.is_empty`
are `true` rather than the request erroring when the underlying data isn't
there yet.

### APIs (`api/routes/workspace.py`)

| Endpoint | Method | Success | Errors | Notes |
|---|---|---|---|---|
| `/api/v1/workspace` | POST | 201, `WorkspaceInvestigation` | 422 (validation) | |
| `/api/v1/workspace` | GET | 200, `WorkspaceListResponse` | — | `WorkspaceListItem` rows omit the three nested payloads by design (metadata only); optional `status`/`severity`/`investigation_type`/`tag`/`q` filters combine with AND; most-recently-updated first. |
| `/api/v1/workspace/{id}` | GET | 200, `WorkspaceInvestigation` | 404, 422 (bad UUID) | |
| `/api/v1/workspace/{id}/timeline` | GET | 200, `Timeline` | 404, 422 | Never mutates the record; recomputed every call. |
| `/api/v1/workspace/{id}/graph` | GET | 200, `EvidenceGraph` | 404, 422 | Never mutates the record; recomputed every call. |
| `/api/v1/workspace/{id}/export` | GET | 200, `InvestigationReport` | 404, 422 | Never mutates the record; recomputed every call. |
| `/api/v1/workspace/{id}` | PUT | 200, `WorkspaceInvestigation` | 404, 422 | Partial update; omitted fields unchanged, explicit `null` clears a field. |
| `/api/v1/workspace/{id}` | DELETE | 204 | 404 | |

**API stability guarantees, verified in this phase:**

- Every operation above returns the same status codes, the same response
  shape, and the same error behavior as when each was first shipped
  (`tests/*/test_no_regression.py`, re-run clean in this phase's
  validation pass).
- `GET .../timeline`, `.../graph`, and `.../export` are idempotent and
  non-mutating: calling any of them any number of times never changes what
  `GET /workspace/{id}` subsequently returns
  (`test_never_mutates_the_saved_investigation` and this phase's
  compatibility-matrix equivalents).
- No endpoint above has been removed, renamed, or had a required field
  added since it first shipped. **Only additive changes are permitted after
  this freeze.**

## Compatibility assessment

Phase 8.5 was asked to *verify*, not invent, backward compatibility across
the realistic shapes a saved record can have. The existing suites already
covered nearly every axis exhaustively, one at a time:

- **No `investigation_summary` at all** — `Timeline`/`EvidenceGraph`/
  `InvestigationReport` are all well-formed and empty, never an error
  (`tests/timeline/test_service.py::test_returns_an_empty_timeline`,
  `tests/graph/test_service.py::test_returns_an_empty_graph`,
  `tests/reporting/test_service.py::TestBuildWithoutSummary`).
- **Finding with no evidence** — contributes no timeline event but still a
  graph node (`tests/timeline/test_engine.py::test_finding_with_no_evidence_produces_no_events`,
  `tests/graph/test_engine.py::test_finding_with_no_relationships_yields_one_node_no_edges`).
- **Single finding, multiple findings, and shared/duplicate evidence across
  findings** (dedup) — extensively covered in both engines' test suites
  (e.g. `test_identical_evidence_cited_by_two_findings_collapses_to_one_event`,
  `test_same_subject_across_two_findings_is_one_node`).
- **Correlation present with no `investigation_summary`** — handled
  gracefully at the graph layer
  (`tests/graph/test_service.py::test_correlation_alone_without_summary_is_handled_gracefully`).
- **Every combination of the three optional sections, through Report and
  the real HTTP API** — this was the one genuinely untested axis: no
  existing test combined "no summary" with "`detection_package` present,"
  or swept the full matrix through `ReportService` and the live API in one
  place. Closed in this phase by
  `tests/reporting/test_compatibility_matrix.py` (36 new tests): six
  representative shapes (bare · detection-only · single finding · multiple
  findings · correlation-only · fully populated), each checked for (a)
  `Timeline`/`Graph` emptiness matching the documented rule exactly, (b)
  `Report.timeline`/`Report.graph` matching the independently-built
  sibling service's own output, (c) `detection_package` surviving
  verbatim regardless of the other two sections' state, and (d) a real
  save-then-export HTTP round trip for every shape.

**Conclusion: fully backward compatible.** No migration logic exists or is
needed — every shape above was already valid under the Phase 8.0–8.4
contracts; this phase only added the cross-cutting test that proves it in
one place.

## Golden coverage

`timeline/` and `graph/` each already have a golden corpus
(`corpus.py`/`golden.json`/`test_golden.py`) covering their own
event/node/edge derivation determinism. `workspace/` and `reporting/` do
not, and this phase adds none for them: `WorkspaceService` has no
derivation logic to snapshot (it is CRUD over a caller-supplied payload),
and `ReportService` has none of its own either — its only two tests that
would matter for a golden snapshot
(`test_timeline_matches_the_independent_timeline_service`,
`test_graph_matches_the_independent_graph_service`) already assert
equality against the sibling services' own (separately gold-tested)
output, which is a strictly stronger check than a frozen JSON snapshot of
`ReportService`'s output alone would be. Adding a redundant golden file for
`reporting/` would duplicate coverage the equality tests already provide
more precisely — skipped per this phase's own "do not duplicate existing
golden tests unnecessarily" instruction.

## Performance baseline

Measured by the new `tests/workspace/perf.py` harness (mirroring the
existing `tests/correlation/perf.py`/`tests/detection/perf.py` convention:
a standalone runnable module plus a `test_perf_smoke.py` that only asserts
the harness runs and reports sane shapes — no timing thresholds in CI,
since those are environment-dependent and would flake on shared runners).
Run via `cd backend && python -m tests.workspace.perf`. All four
operations are pure/offline (workspace persistence uses real local-disk
I/O in a temp directory; the other three are pure in-memory computation) —
no network, no AI.

Measured on this session's runner (findings per investigation; each finding
carries one timestamped evidence item):

| Findings | Save (median) | Load (median) | Timeline build | Graph build | Report build | JSON export |
|---:|---:|---:|---:|---:|---:|---:|
| 5 | 0.08 ms | 0.05 ms | 0.03 ms | 0.02 ms | 0.05 ms | 0.03 ms |
| 25 | 0.26 ms | 0.18 ms | 0.14 ms | 0.10 ms | 0.25 ms | 0.15 ms |
| 100 | 0.77 ms | 0.91 ms | 0.62 ms | 0.41 ms | 1.05 ms | 0.60 ms |
| 400 | 3.29 ms | 4.24 ms | 2.61 ms | 1.73 ms | 4.67 ms | 2.56 ms |

Peak allocation at 400 findings (well past any realistic single
investigation): workspace load ≈ 2.2 MiB, timeline build ≈ 520 KiB, graph
build ≈ 708 KiB, report build ≈ 1.17 MiB.

**Per-finding cost is linear across the whole range for every operation**
(spread of per-finding µs cost between the smallest and largest size:
workspace load 1.50x, timeline 1.14x, graph 1.21x, report build 1.17x,
export 1.18x — all comfortably under the harness's 3.0x "investigate"
threshold). No optimization work is warranted or was performed; this is a
baseline recording, not a response to any measured bottleneck.

## Regression assessment

**No duplicated analytical logic exists between Timeline, Graph, Report,
and Export.** Traced end to end for this phase:

- `TimelineService.build()` and `GraphService.build()` each read
  `WorkspaceInvestigation` directly and independently; neither imports or
  calls the other.
- `ReportService.build()` (`reporting/service.py`) contains no
  event/node/edge derivation of its own — its entire body is
  `InvestigationReport(report_schema_version=..., investigation=record,
  timeline=self._timeline.build(record), graph=self._graph.build(record))`.
  It depends on `TimelineService`/`GraphService` as collaborators, exactly
  once each, rather than re-implementing anything.
- The `/export` route (`api/routes/workspace.py`) does not call
  `TimelineService`/`GraphService` directly — it calls `ReportService`
  only, which is itself the sole caller of both. There is exactly one code
  path from a saved record to a `Timeline`/`EvidenceGraph`, whether reached
  via the dedicated routes or via `/export`.
- The frontend's `graphAdapter.ts` (Phase 8.3, reused unchanged by the
  Phase 8.4 report view) performs no independent derivation: its only
  `.sort()` call orders the *distinct node-type list for a UI filter
  dropdown*, not nodes/edges themselves, and it contains no timestamp
  parsing, no relationship inference, and no evidence re-interpretation —
  confirmed by inspection in this phase. It is a pure reshaping of
  already-computed API data into React Flow's node/edge format.
- The report frontend's two new pure functions (`summarizeProviders`,
  `countNodesByType`) tally fields the API response already carries
  (`sources`, `node_type`) — they do not recompute anything Timeline,
  Graph, or Report itself computed.

No consolidation work was needed or performed; the architecture already
had one derivation path per concern.

## Known limitations

Consolidated from the individual phase documents; still true, not changed
by this phase:

- **Timeline** derives events only from evidence carrying an explicit,
  timezone-aware `observed_at`. Missing or naive timestamps are silently
  omitted, never invented or estimated. `DetectionPackage` and
  `CorrelationSummary` carry no per-item evidence timestamp (only a
  package/summary-level `generated_at`, describing when the output was
  *computed*, not when a security event was *observed*) and so contribute
  no timeline events.
- **Graph** never infers a relationship from mere co-occurrence; every
  edge traces to an explicit `Relationship` or `CorrelationRelationship`
  already present in the source data.
- **The Report's Threat Intelligence section is a provider-attribution
  tally, not a reputation dump** — `AggregatedResult`/`ProviderSummary`
  (raw per-provider status/reputation) and `Reference`/`AttributedReference`
  (external citation URLs) are never persisted on a saved
  `WorkspaceInvestigation`; only `AttributedEvidence`/`AttributedRelationship`
  (which carry `sources`) are. This is a data-availability fact, not a
  bug, and was a deliberate Phase 8.4 design decision.
- **`LocalFileStorage` is local-disk, single-user, no auth, no database.**
  On serverless deployments (e.g. Vercel), the configured
  `THREATLENS_WORKSPACE_DIR` may point at ephemeral storage (`/tmp`) that
  does not persist across cold starts — documented in the Vercel
  production-fix work; unchanged by this phase.
- **No case management, SOAR, AI-generated content, collaboration,
  comments, evidence editing, or workflow** exist in this stack, by design
  — see Explicit Non-Goals below.

## Future extension guidance

A later phase that wants to extend this platform without breaking the
freeze above should:

- Add new fields to `WorkspaceInvestigation` (or a nested engine output)
  **only as optional, safely defaulted fields** — every existing consumer
  (`Timeline`, `Graph`, `Report`, the frontend) must keep working unchanged
  against a record that predates the new field.
- Model a new derived projection as a new, independent `XService.build(record)
  -> XModel`, following the exact `TimelineService`/`GraphService` pattern
  — stateless, side-effect-free, no dependency on any *other* projection
  service unless composing them the way `ReportService` does. Add it as a
  new sibling route; never fold new derivation logic into an existing
  service.
- Bump the relevant version constant
  (`TIMELINE_FRAMEWORK_VERSION`/`GRAPH_FRAMEWORK_VERSION`/
  `REPORTING_FRAMEWORK_VERSION`/`WORKSPACE_FRAMEWORK_VERSION`) the moment a
  change is anything other than purely additive — these constants exist
  specifically to make a future breaking change discoverable rather than
  silent.
- Extend `InvestigationReport` by adding a new top-level field (composing a
  new service's output), never by changing the meaning of `investigation`,
  `timeline`, or `graph`.
- Re-run `tests/reporting/test_compatibility_matrix.py` (extending its
  scenario list if the new field changes what "empty" means for any
  projection) before considering any such change complete.

## Explicit non-goals (unchanged, still out of scope)

Case management, SOAR, detection generation changes, AI-generated report
content, collaboration/comments/tags editing beyond what already exists,
workflow automation, notifications, new report sections, new graph/timeline
features, persistent-storage redesign (e.g. a database backend), and
Phase 9 generally. None of these were touched by this phase, and this
document does not authorize starting any of them.

## Testing

This phase added 40 new backend tests, all offline, all in the four
in-scope packages:

- `tests/reporting/test_compatibility_matrix.py` — 36 tests: the
  platform-compatibility matrix described above (6 scenarios × 6
  assertions, spanning service-level equality checks and a real HTTP
  save-then-export round trip per scenario).
- `tests/workspace/perf.py` + `tests/workspace/test_perf_smoke.py` — a
  performance-baseline harness plus 4 smoke tests asserting it runs and
  reports internally consistent, non-negative shapes (no CI timing
  assertions, matching the established convention).

No existing test was modified, weakened, or removed. See Validation
Results in the Phase 8.5 completion report for the full-suite run this
phase's changes were verified against.
