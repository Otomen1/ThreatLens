# Phase 8.4 — Workspace Export & Investigation Reporting

## Status

Complete. A pure, deterministic **projection** over a saved investigation's
existing outputs and existing derived projections (Timeline, Evidence
Graph) — not a new intelligence engine, not a fourth analytical pipeline,
and not an AI-generated report. It adds a JSON export contract and an
analyst-facing, print-friendly report view, both built from the same one
deterministic call.

## Purpose

A saved `WorkspaceInvestigation` (Phase 8.0) already carries everything an
analyst needs — findings, recommendations, correlation, and (via Phase
8.1/8.2) a Timeline and an Evidence Graph — but there was no way to export
it as a single structured document, or to view/print it as a professional
report distinct from the interactive workspace UI. Phase 8.4 answers that
by composing what already exists into one envelope and rendering it two
ways: a downloadable JSON file, and a dedicated report page suited to the
browser's native print/Save-as-PDF.

## Architecture

```
Saved Workspace Investigation
        │
        ├── Existing Investigation Summary   (Reasoning Engine, verbatim)
        ├── Existing Correlation Summary     (Correlation Engine, verbatim, if attached)
        ├── Existing Timeline Projection     (Phase 8.1 TimelineService, unchanged)
        └── Existing Evidence Graph Projection (Phase 8.2 GraphService, unchanged)
                        │
                 ReportService.build(record)
                        │
                 InvestigationReport
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
       JSON Export           Analyst Report View
    (GET .../export)        (/workspace/{id}/report)
                                   │
                          Browser Print / Save as PDF
```

`backend/src/threatlens/reporting/`:

| Module | Role |
|---|---|
| `models.py` | `InvestigationReport` — a frozen envelope; `REPORTING_FRAMEWORK_VERSION`. |
| `service.py` | `ReportService` — composes `TimelineService`/`GraphService` (injected, not reimplemented) with the saved record. |

There is no `engine.py` and no `exceptions.py`: unlike Timeline/Graph,
`ReportService` has no derivation algorithm of its own to isolate — its
entire job is composing three already-existing, already-tested objects
into one envelope. Like Timeline (Phase 8.1) and Graph (Phase 8.2), a
report is always derivable from a saved record (there is no failure mode
of this framework's own); the only error path is the existing "record not
found," handled identically to the sibling `/timeline`/`/graph` routes.

Data flow: `GET /api/v1/workspace/{id}/export` → `WorkspaceService.get(id)`
(existing, unchanged — 404 if missing) → `ReportService.build(record)` →
internally calls `TimelineService.build(record)` and
`GraphService.build(record)` (the exact same objects the sibling
`/timeline`/`/graph` routes return) → `InvestigationReport`. Nothing is
written back to the saved record; nothing is cached; every call recomputes
from the same source, deterministically.

## Report data contract

```python
class InvestigationReport(BaseModel):    # frozen
    report_schema_version: str            # "1.0" — this envelope's own version
    investigation: WorkspaceInvestigation # the saved record, verbatim
    timeline: Timeline                    # identical to GET .../timeline
    graph: EvidenceGraph                  # identical to GET .../graph
```

No dedicated report-only fields were invented beyond
`report_schema_version`. Per the brief's explicit preference ("if the
saved Workspace record already provides a suitable JSON export contract,
reuse it and add only minimal export metadata"), `investigation` is the
existing `WorkspaceInvestigation` model reused wholesale — not duplicated,
not renamed, not re-shaped. The one genuinely new piece of information is
the schema version, kept deliberately distinct from
`WORKSPACE_FRAMEWORK_VERSION`/`TIMELINE_FRAMEWORK_VERSION`/
`GRAPH_FRAMEWORK_VERSION`/each engine's own version: those describe their
own subsystem; `report_schema_version` describes only this envelope's own
shape, so a future addition to the export contract (e.g. a new top-level
section) doesn't need to be inferred from unrelated version numbers nested
inside it.

**No `exported_at` timestamp is included.** The brief allows one but
requires it be treated as pure request metadata, excluded from semantic
identity — the simplest way to honor that, and to keep the strongest
possible determinism guarantee (byte-identical, not just
semantically-identical), is to not add a field that provides no analytical
value in the first place.

## Determinism

Building the same saved record twice always produces a byte-identical
`InvestigationReport`:

- `investigation` is copied verbatim — no field is recomputed.
- `timeline`/`graph` are the exact same deterministic projections Phase
  8.1/8.2 already proved stable (stable content-addressed ids, stable
  ordering, input-order independence) — `ReportService` does not
  re-implement or re-derive either.
- No random UUID, no wall-clock read, no request-position-based id exists
  anywhere in this framework's own code.

Proven directly: `test_service.py::TestDeterminismAndSafety::test_repeated_build_is_byte_identical`,
and `test_api.py`'s `test_repeated_fetch_is_byte_identical` /
`test_timeline_section_matches_the_dedicated_timeline_route` /
`test_graph_section_matches_the_dedicated_graph_route` (the export's
sections are asserted equal to the sibling routes' own independent output,
not merely "similar").

## Evidence provenance

Every existing reference chain is preserved untouched, because nothing is
copied out of its original shape:

- A `Recommendation.finding_ids` still points at the exact `Finding.id`s in
  the same report's Findings section.
- A `Finding.evidence`/`.relationships` entry still carries its original
  `AttributedEvidence`/`AttributedRelationship` (`sources`, i.e. which
  provider(s) reported it) — rendered inline per finding, *and*
  additionally summarized by provider in the Threat Intelligence section
  (see below), both views over the same underlying data.
- A `CorrelationObservation.evidence[].finding_id` still names the finding
  it cites; `CorrelationRelationship.source_finding_id`/`target_finding_id`
  still name the two findings it links.
- A `GraphEdge.evidence_references`/`.source_references` and a
  `TimelineEvent.evidence_references`/`.source_id` are rendered exactly as
  `GraphService`/`TimelineService` already produce them — `ReportService`
  never touches either.

No new provenance link of any kind is invented; where the saved record
doesn't carry a chain (e.g. no per-citation `Reference`/URL — see "Known
limitations"), the report simply doesn't fabricate one.

## JSON export

`GET /api/v1/workspace/{investigation_id}/export`, added to the existing
workspace router as a sibling of Phase 8.1's `/timeline` and Phase 8.2's
`/graph` — same pattern, same 404 handling, same "every existing
workspace/timeline/graph operation is unchanged" guarantee (see
`test_no_regression.py`). Response model: `InvestigationReport` (above).

No section is fabricated when its source is absent: `investigation.correlation_summary`
is `null` exactly when the saved record has none attached;
`investigation.detection_package` is `null` exactly when none is attached;
`timeline.events`/`graph.nodes` are empty tuples exactly when no
timestamped evidence / no evidence-supported entity exists — all identical
to how the sibling `/timeline`/`/graph` endpoints already represent
"nothing here," never a different, report-specific empty convention.

No external provider is called, no AI is invoked, and the saved record is
never mutated — confirmed by `test_service.py::TestDeterminismAndSafety::test_does_not_mutate_the_saved_record`
and `test_api.py::test_never_mutates_the_saved_investigation`.

## Analyst report view

`frontend/app/workspace/[id]/report/page.tsx` — a dedicated route, fetched
in one call via `getInvestigationReport()`. Visually distinct from the
interactive workspace page: every section renders fully expanded (a
printed page has no collapse-to-click state), uses a narrower
report-appropriate width, and is styled with Tailwind's `print:` variant
throughout — a dark on-screen theme (consistent with the rest of the app)
that becomes a clean, light, ink-conscious layout under `@media print`
(verified visually via Playwright's `emulate_media("print")`).

Components, `frontend/components/workspace/report/`:

| Component | Renders |
|---|---|
| `ReportHeader` | ThreatLens wordmark, investigation id/title/entity/saved timestamp, schema version. |
| `ReportAssessment` | Posture, overall confidence, finding/recommendation counts, engine version — the same deterministic fields `InvestigationSummaryCard` already shows, fully expanded. |
| `ReportFindings` | Every `Finding`, fully expanded: severity, title, categories, rule ids, confidence, subject, rationale, evidence, relationships. |
| `ReportRecommendations` | Every `Recommendation`: action, category, priority, target, rationale, rule id, `finding_ids`. |
| `ReportThreatIntelligence` | A provider-attribution table: which existing evidence/relationship `sources` contributed, how many items each, and to which findings — a source-first complement to Findings' finding-first view. Pure, tested (`summarizeProviders`), alphabetically sorted for determinism. |
| `ReportCorrelation` | Every `CorrelationObservation` (id, category, title, summary, subject, cited evidence, relationships) or a clear empty state. |
| `ReportTimeline` | The existing `Timeline.events`, as a table, or a clear empty state. |
| `ReportGraphSummary` | A concise textual/tabular summary of the existing `EvidenceGraph` — node-type counts (`countNodesByType`, pure, tested), a node table, an edge table — deliberately **not** the interactive React Flow canvas (Phase 8.3), which has no clean print representation and isn't required for the report to remain useful. |
| `ReportDetections` | Only rendered when `detection_package` is attached; artifact table. Detection Engineering is never re-run. |
| `ReportActions` | Export JSON / Print Report buttons; `print:hidden`. |

## Presentation adapter

There is no new adapter module analogous to Phase 8.3's `graphAdapter.ts`
— every report component reads the existing `InvestigationReport`/
`WorkspaceInvestigation`/`Finding`/`Recommendation`/`CorrelationSummary`/
`Timeline`/`EvidenceGraph` fields directly and formats them for display
using the *existing* shared helpers (`severityLabel`/`severityClasses`,
`confidenceBandLabel`/`confidenceBandClasses`, `formatRelationship`,
`formatTargetType`, `titleCase`) already established in
`lib/investigation.ts` and reused by `FindingsSection`/`RecommendationRollup`/
`InvestigationSummaryCard` — no formatting logic is duplicated. The two
small pure functions this phase does add (`summarizeProviders`,
`countNodesByType`) are presentation-only tallies over already-existing
`sources`/`node_type` fields — grouping and counting, never inventing a
relationship, entity, or severity.

## JSON export UX

An "Export JSON" action exists on both the report page and the existing
workspace detail page (`frontend/app/workspace/[id]/page.tsx`, next to a
new "View Report" link). Both fetch (or reuse) the exact
`GET .../export` response and trigger a client-side download via
`frontend/lib/download.ts`'s `triggerJsonDownload()` — no server-side file
generation, no new backend endpoint beyond the one export route.
Filenames are `threatlens-{investigation_id}.json`, with the id passed
through `sanitizeFilenameSegment()` (strips anything outside
`[a-zA-Z0-9-]`) before use — defense in depth, since a workspace
investigation id is already a server-validated UUID by the time it reaches
the frontend.

## Print / Save as PDF

"Print Report" calls the browser's native `window.print()` — no server-side
PDF engine, no headless-Chromium service, no new dependency. Print-specific
styling is Tailwind `print:` utility classes applied directly in each report
component: `print:hidden` on interactive-only controls (the actions bar,
the back-navigation link); `print:bg-white`/`print:text-black`/
`print:border-zinc-*` throughout, so the printed page is light and
ink-conscious rather than inheriting the app's dark theme; `print:break-inside-avoid`
on finding/recommendation/correlation cards so a printed page doesn't split
a card mid-way where practical; every severity/confidence badge keeps its
text label (not just a color swatch), so meaning survives black-and-white
printing.

## Security considerations

- **Filename safety**: `sanitizeFilenameSegment()` strips every character
  outside `[a-zA-Z0-9-]` before it reaches a downloaded filename — no path
  traversal, no injected extension, even though the input (a UUID) is
  already safe by construction.
- **No server-side file writes**: the JSON download is generated entirely
  client-side from an already-fetched HTTP response (`Blob` + a temporary
  object URL); nothing touches the server's filesystem.
- **No external requests during export/report generation**: `ReportService.build()`
  only reads the already-in-memory saved record and calls the two existing,
  offline, pure sibling services.
- **No secrets/environment variables exposed**: the report surfaces only
  fields already present on `WorkspaceInvestigation`/`Timeline`/`EvidenceGraph`
  — none of which carry provider API keys or server configuration.
- **No unsafe HTML rendering**: every report component renders plain React
  text nodes; `dangerouslySetInnerHTML` is not used anywhere in this phase.

## Known limitations

- **No per-citation external `Reference`/URL is reproducible.** `Reference`/
  `AttributedReference` (title, url, description) exist only on
  `AggregatedResult`, which is **not** persisted on a saved
  `WorkspaceInvestigation` — only the Reasoning Engine's derived
  `InvestigationSummary` is (itself embedding evidence via
  `Finding.evidence: list[WeightedEvidence]`, which carries `sources`
  (provider names) but no reference URL). The Threat Intelligence
  section's provider-attribution table is the closest available,
  fully-real substitute; a dedicated "References Appendix" was
  deliberately not built as a near-empty placeholder for data the saved
  record never received. A future phase could persist per-provider
  reference data on save if this traceability is needed.
- **No per-provider `status`/`reputation`.** `ProviderSummary` (a
  provider's overall health/reputation for the investigated entity) is
  likewise not persisted on the saved record — only per-evidence
  attribution (`sources`) is. The Threat Intelligence section reports
  contribution counts and finding attribution, not per-provider status.
- **The Evidence Graph is a table/summary, not the interactive canvas.**
  By design (see brief): the Phase 8.3 React Flow visualization has no
  clean print representation; a concise node/edge table conveys the same
  underlying facts (ids, types, severities, relationships) without
  requiring a canvas screenshot or a print-specific graph-rendering
  library.
- **No golden-corpus regression suite for reporting specifically.** Given
  `InvestigationReport` is a thin composition of two already
  golden-corpus-tested projections (Timeline, Graph) plus the unchanged
  `WorkspaceInvestigation` model, a third golden corpus would duplicate
  coverage rather than add real value; determinism/composition is instead
  covered directly (see "Determinism").

## Future extensions (explicitly out of scope for this phase)

Per the brief: AI-generated report content, report editing, scheduled/emailed
reports, cross-investigation reports, server-side PDF generation, and any
new analytical engine are not started. Natural next steps this phase's
design already accommodates without rework: persisting per-provider
reference/reputation data at save time (would slot into the existing
Threat Intelligence section without a contract change); an opt-in
graph-image export (would live entirely in `ReportGraphSummary` without
touching `ReportService`/`InvestigationReport`).

## Testing

`backend/tests/reporting/` (41 tests):

- **`test_models.py`** — the `InvestigationReport` envelope: frozen,
  required non-empty schema version, verbatim field carriage, JSON
  round-tripping.
- **`test_service.py`** — composition correctness: with/without an
  attached `investigation_summary`, the report's `timeline`/`graph`
  sections are asserted **equal** to independently-constructed
  `TimelineService`/`GraphService` output (not merely present);
  determinism (repeated build, a second service instance); non-mutation
  of the saved record.
- **`test_api.py`** — the full HTTP contract: `200`/`404`/`422`, response
  shape, the export's `investigation`/`timeline`/`graph` sections compared
  directly against the plain `GET /workspace/{id}`, `GET .../timeline`,
  and `GET .../graph` responses (proving one shared contract, not a
  parallel one); a real `/investigate` summary round-tripped through
  save → export; repeated-fetch byte-identity; non-mutation; every
  sibling workspace/timeline/graph operation still works alongside the
  new route.
- **`test_no_regression.py`** — every pre-Phase-8.4 route (via the OpenAPI
  schema), every engine version constant (Reasoning, Detection,
  Correlation, Timeline, Graph), all unchanged; the new export route is
  purely additive.

Frontend: 20 new tests — 5 in `lib/api.test.ts` (`getInvestigationReport`),
6 in `ReportThreatIntelligence.test.ts` (`summarizeProviders`: empty case,
single-provider counting, multi-provider attribution of one evidence item,
alphabetical determinism regardless of finding order, per-finding-title
deduplication), 5 in `ReportGraphSummary.test.ts` (`countNodesByType`:
empty, grouping, alphabetical determinism, no invented types), 4 in
`lib/download.test.ts` (`sanitizeFilenameSegment`). Component-rendering
correctness (report sections, states, actions) was verified via real
browser testing (below) rather than new component-rendering test
infrastructure — consistent with this codebase's existing convention
(no `.test.tsx`/Testing-Library setup exists for *any* component in this
project; UI correctness has always been proven by real-browser
verification, not component unit tests, and Phase 8.4 follows that same
established pattern rather than introducing a new one).

One incidental fix: `frontend/vitest.config.ts` had no `resolve.alias` for
`@/*` (only `tsconfig.json` declared it), so any test importing a `.tsx`
component that itself imports via the `@/` alias failed to resolve —
`@/lib/api` happened to already be exercised directly by existing test
files and so "worked," while `@/lib/investigation` (needed by
`ReportGraphSummary.tsx`) had never been exercised by any test and did
not. Added a one-line `resolve.alias` mirroring `tsconfig.json`'s existing
`"@/*": ["./*"]` mapping — a test-tooling correctness fix, not an
application change.

Full suite after this phase: **2,729 backend tests passed, 1 skipped**
(was 2,688). Ruff and mypy (`--strict`) clean across 189 source files (was
186). Frontend: 177 Vitest tests passed (was 157); production build
clean, including the new `/workspace/[id]/report` route.

## Readiness review

**GO.**

- No engine changes: Reasoning, Detection, Correlation, Exposure,
  Identity, Timeline, and Graph are byte-for-byte unmodified (engine
  version constants unchanged; verified by `test_no_regression.py`).
- No existing API changes: every pre-Phase-8.4 workspace/timeline/graph
  operation keeps its exact HTTP methods and response shape; the new
  export route is purely additive.
- No AI, no invented findings/recommendations/relationships/timestamps —
  every report field traces to an existing `WorkspaceInvestigation`,
  `Timeline`, or `EvidenceGraph` field, or is a pure count/grouping over
  one of those.
- Deterministic and safe by construction and by test: repeated
  builds/fetches are byte-identical; the saved record is never mutated;
  no external provider or AI call occurs during report generation.
- Existing tests: full backend suite green, **2,729 passed / 1 skipped**
  (up from 2,688 — the delta is entirely new reporting tests). Frontend:
  177 Vitest tests passed (up from 157), production build clean.
- Manually verified end-to-end in a real browser against a live backend
  with a hand-built investigation (real MITRE ATT&CK findings/
  recommendations plus an attached correlation observation): correct
  report header/assessment/findings/recommendations/threat-intelligence/
  correlation/timeline/graph-summary content; correct empty states for an
  investigation with no attached results; correct error state for an
  unknown investigation id; "Export JSON" produces valid, matching JSON
  from both the workspace page and the report page; "Print Report"
  invokes the browser's native print; print-media emulation confirmed a
  clean, light, readable printed layout with interactive controls hidden;
  the sibling interactive Evidence Graph (Phase 8.3) and Timeline remained
  fully functional and unaffected.
