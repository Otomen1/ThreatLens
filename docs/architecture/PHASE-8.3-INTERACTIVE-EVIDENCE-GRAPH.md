# Phase 8.3 — Interactive Evidence Graph Visualization

## Status

Complete. A **frontend-only, presentation-layer** upgrade of Phase 8.2's plain
node/edge lists into an interactive, explorable graph. It consumes the
existing `GET /api/v1/workspace/{id}/graph` response exactly as returned —
**no backend change, no new engine, no new API field.** Every node, edge, id,
type, label, severity, and reference on screen already existed in the
`EvidenceGraph` API model; this phase only decides where it sits on screen and
which of it is currently visible.

## Objective

Phase 8.2 shipped a correct but static UI: nodes and edges as `<ul>` lists,
readable but not explorable at a glance for a larger investigation. Phase 8.3
replaces that rendering with a real node-link canvas — pan, zoom, fit-to-view,
click-to-inspect, search, and filter — so an analyst can visually navigate an
investigation's evidence graph the way they already do in the Timeline and
Findings sections, without changing one bit of what the graph *means*.

## Scope

**In scope:** a graph-visualization library, a pure presentation adapter, a
custom node renderer, an inspector panel, search, filtering, and the
supporting tests/docs — all inside `frontend/components/workspace/graph/` and
the one integration point in `frontend/app/workspace/[id]/page.tsx`.

**Out of scope (frozen, untouched this phase):** `backend/src/threatlens/graph/`
(`models.py`, `engine.py`, `service.py`), the `GET /api/v1/workspace/{id}/graph`
route, every other engine (Reasoning, Detection, Correlation, Exposure,
Identity, Timeline), and `frontend/lib/api/workspace.ts`'s existing
`GraphNode`/`GraphEdge`/`EvidenceGraph` types and `getInvestigationGraph()`
client. Confirmed unmodified by `git diff --stat` against this phase's commits
and by the unchanged `graph_version`/engine test suite.

## Architecture

```
frontend/components/workspace/graph/
├── graphAdapter.ts        # pure presentation adapter (no React)
├── GraphCanvasNode.tsx    # custom React Flow node renderer
├── GraphInspector.tsx     # node/edge detail panel
├── GraphToolbar.tsx       # search input + filter chips
└── EvidenceGraphView.tsx  # container: wires adapter + toolbar + canvas + inspector
```

Data flow, extending Phase 8.2's diagram:

```
GET /api/v1/workspace/{id}/graph   (unchanged, Phase 8.2)
        │
        ▼
  EvidenceGraph  (nodes, edges — the API model, unchanged)
        │
        ▼
  graphAdapter.toFlowGraph()   ← pure, presentation-only
        │
        ▼
  React Flow  (canvas, zoom/pan/fit-view, click selection)
        │
        ├── GraphToolbar    (search + filter → visibility only)
        └── GraphInspector  (selected node/edge → its existing fields, verbatim)
```

`EvidenceGraphView` is the only component that talks to React Flow directly;
`GraphCanvasNode`, `GraphInspector`, and `GraphToolbar` are presentational and
receive already-computed data as props. No component re-fetches, re-derives,
or duplicates what `graphAdapter.ts` computes.

## Selected visualization library

**`@xyflow/react` (React Flow) v12.11.2** — the only new dependency this phase
adds.

Alternatives considered and rejected:

| Library | Why not |
|---|---|
| **Cytoscape.js** | General-purpose graph engine with its own scene-graph and styling DSL; would require a second adapter layer and duplicate React's rendering model alongside it. Heavier than this scope needs. |
| **vis-network** | Physics-based layout by default; steering it into a deterministic, non-physics layout fights the library rather than using it. Less actively maintained than React Flow. |
| **visx / raw D3** | Would mean hand-rolling node dragging, edge routing, zoom/pan, and hit-testing from primitives — significant custom code for behavior React Flow already provides, and the brief explicitly prefers "custom SVG/D3 only if... no lightweight library exists," which is not the case here. |
| **React Flow (`@xyflow/react`)** | **Selected.** React-first and TypeScript-native (no wrapper layer needed), actively maintained (v12 line, regular releases), purpose-built for exactly this shape of problem (typed nodes + labelled edges + inspection), and ships pan/zoom/fit-view/click-selection out of the box via `<Controls>` — the "prefer existing dependencies... else exactly one new, lightweight, actively maintained library" criterion points here directly. Confirmed compatible with the project's React 19 peer dependency before adding it. |

No second graph library was added; no existing dependency already covered
this need (checked `frontend/package.json` — no graph-rendering library was
present before this phase).

## Presentation adapter (`graphAdapter.ts`)

The adapter is deliberately the only place that touches both the API shape
and React Flow's shape. It has no React import and no side effects, so it is
unit-testable as plain data transforms:

- **`toFlowGraph(graph: EvidenceGraph)`** — maps every `GraphNode` to a React
  Flow `Node` and every `GraphEdge` to a React Flow `Edge`, 1:1. `id`,
  `data.apiNode`/`data.apiEdge`, `source`, `target` are copied verbatim; the
  only computed value is `position` (see layout below) and a display-only
  edge `label` (`relationship_type` with underscores replaced by spaces — a
  formatting transform, not a semantic one; the underlying `data.apiEdge.relationship_type`
  is untouched, asserted directly by `graphAdapter.test.ts`).
- **`layoutPositions(nodes)`** — a deterministic column-by-`node_type` layout:
  one column per distinct `node_type` (columns ordered alphabetically, the
  same key the backend's own `sort_nodes` already orders by), nodes stacked
  top-to-bottom within their column in the exact order the API returned them.
  Position is a pure function of `(node_type, index-within-type)` — no
  physics, no iteration, no randomness, and no clustering/centrality
  computation, satisfying the brief's "do not implement custom graph physics…
  unless genuinely necessary" and "no clustering, no centrality algorithms."
  Grouping by column is a rendering convenience keyed to an existing data
  field (`node_type`), not a claim about chronology or causality between
  columns.
- **`GraphFilters` / `EMPTY_FILTERS` / `hasActiveFilters`** — a plain value
  object (`query`, `nodeTypes`, `severities`, `relationshipTypes`) with no
  hidden state.
- **`matchesQuery(node, query)`** — case-insensitive substring match against
  the node's own existing `value`, `label`, and `node_type`. No fuzzy or
  semantic matching, no backend search call.
- **`visibleNodeIds(nodes, filters)` / `visibleEdgeIds(edges, visibleNodes, filters)`**
  — computes which already-existing node/edge ids should currently be shown.
  An edge is visible only if **both** its endpoints are visible — a hidden
  endpoint never leaves a "floating" edge implying a connection the analyst
  can't see the ends of. Filtering only changes a React Flow `hidden` flag in
  `EvidenceGraphView`; the node/edge arrays passed into the adapter, and the
  `EvidenceGraph` prop itself, are never mutated, sliced, or re-created.

## Node rendering (`GraphCanvasNode.tsx`)

A custom React Flow node type (`EVIDENCE_NODE_TYPE = "evidenceNode"`)
displaying, per node, only fields that already exist on `GraphNode`://
a `node_type` badge (underscore-formatted for readability), a severity badge
using the existing shared `severityClasses`/`severityLabel` helpers (already
used elsewhere in the workspace UI, not reimplemented), and the node's
`label`. Selection state (`selected`) drives a border/background highlight
only — purely visual, not a data change.

## Edge rendering

Edges use React Flow's built-in labelled-edge rendering (no custom edge
component was needed): the label is the display-only formatted
`relationship_type` from `toFlowGraph`, and a selected edge is highlighted
with a distinct stroke color/width, computed in `EvidenceGraphView` from the
current `selection` state — again presentational only.

## Inspection (`GraphInspector.tsx`)

Renders the full existing field set of whichever node or edge is currently
selected, verbatim and untruncated (`break-words`, not `truncate`, so long
values remain fully inspectable):

- **Node:** `node_id`, `node_type`, `value`, `severity` (if present),
  `source_references` (joined, or "none"), `metadata` (if non-empty).
- **Edge:** `edge_id`, `relationship_type`, resolved source/target labels
  (via a `nodesById` lookup map, falling back to the raw id if a lookup somehow
  misses), `explanation` (if present), `evidence_references`, `source_references`.

No field is computed, summarized, or paraphrased — every displayed value is a
direct property read, so the inspector can never show something the API
didn't already return.

## Search (`GraphToolbar.tsx`)

A single text input filters against already-loaded graph data client-side
(`matchesQuery`) — no new backend search endpoint, no fuzzy/semantic
matching, no AI. Typing opens a dropdown of matching nodes (type badge +
label, capped at 20 shown); selecting a result sets it as the current
inspector selection. Clearing the query closes the dropdown; it does not
affect canvas visibility on its own — see Filtering.

## Filtering (`GraphToolbar.tsx` + `graphAdapter.ts`)

Toggleable chips for every distinct `node_type`, `severity` (including a
"none" chip for null-severity nodes), and `relationship_type` actually
present in the loaded graph — options are derived from the data, never a
fixed list that could drift from what a given investigation contains.
Multiple active filters combine with AND semantics (`visibleNodeIds`'s test
coverage includes a combined type+severity case). A "Reset filters" control
appears only when at least one filter is active (`hasActiveFilters`) and
clears back to `EMPTY_FILTERS`. Filtering is presentation-only: it changes
which existing elements are visible on the canvasu2014it never removes, reorders,
or recomputes the underlying `graph.nodes`/`graph.edges` arrays, and the
`EvidenceGraph` object passed to `EvidenceGraphView` is never mutated.

## Controls (pan / zoom / fit-to-view)

Provided entirely by React Flow's built-in `<Controls>` component
(`showInteractive={false}` to hide the lock-canvas toggle, which this phase
has no use for) plus `<Background>` for the dotted canvas backdrop.
`fitView` is set on the `<ReactFlow>` element so a freshly loaded graph
starts framed in view; `minZoom`/`maxZoom` bound the zoom range to sane
values. No custom zoom/pan code was written.

## Workspace integration

`frontend/app/workspace/[id]/page.tsx`'s existing `GraphSection` (added in
Phase 8.2) is unchanged in its data-fetching/disclosure logic (same
collapsed-by-default, lazy-fetch-on-first-expand, loading/failed/empty state
handling as before). Only its **rendering** of a loaded, non-empty graph
changed: the previous inline `<ul>` node list and `<ul>` edge list, and the
`selectedNodeId`/`nodesById` state that supported the old click-to-expand
list-item behavior, were removed and replaced with a single
`<EvidenceGraphView graph={graph} />`. The loading, failed, and empty states
(including the "No evidence-supported entities" empty-state message) are
byte-for-byte unchanged — this phase touched only the populated-graph render
branch. The section remains directly below Timeline, on the same
`/workspace/[id]` route; no new route was added.

## Lazy loading

`EvidenceGraphView` and its React Flow dependency are only ever mounted once
`GraphSection` has already fetched a non-empty graph on first expand
(unchanged Phase 8.2 behavior) — the canvas and its CSS are not part of the
initial page bundle's critical path for an analyst who never opens the Evidence
Graph section.

## States handled

Loading, failed, and empty states are the existing `GraphSection` states,
unchanged. Within a loaded, non-empty graph, `EvidenceGraphView` itself
handles: default (nothing selected — inspector shows a prompt), selected-node,
selected-edge, active-search (dropdown open), and active-filter (chips
highlighted, Reset control shown, canvas visibility updated) — verified for a
graph with edges, a graph with nodes but no edges ("solo" investigation), and
the zero-node empty-graph case (which never mounts the canvas at all).

## Evidence integrity invariants

All ten hold by construction, not by convention:

1. **Node/edge identity** — `id`s in `toFlowGraph` are `node.node_id`/`edge.edge_id`
   verbatim; never regenerated, truncated, or rehashed on the frontend.
2. **Relationship types** — `data.apiEdge.relationship_type` is the exact API
   string; only the *displayed label* is underscore-formatted, asserted
   distinctly from the underlying data in `graphAdapter.test.ts`.
3. **Node types** — same treatment as relationship types; `data.apiNode.node_type`
   is never altered, only its displayed badge text.
4. **Severity** — read directly from `apiNode.severity` through the existing
   shared `severityClasses`/`severityLabel` helpers; never computed, blended,
   or re-derived on the frontend.
5. **Source/evidence references** — `source_references`/`evidence_references`
   are rendered as-is (joined for display) in `GraphInspector`; never filtered,
   summarized, or reordered.
6. **No invented nodes** — `toFlowGraph`'s node array has the same length as
   `graph.nodes` always; proven by dedicated adapter tests.
7. **No invented edges** — same guarantee for edges; an edge is additionally
   never shown with a dangling/hidden endpoint (see `visibleEdgeIds`).
8. **Filtering changes visibility only** — `hidden` is a React Flow rendering
   flag; the `graph` prop and the arrays derived from it are never mutated,
   spliced, or re-ordered by any filter operation.
9. **Search never mutates** — `matchesQuery`/`visibleNodeIds` are pure
   predicates over existing data; a search has no write path back into the
   graph.
10. **No persistence of view state** — layout, selection, search text, and
    filters are all in-memory React state, reset on navigation/reload; nothing
    about the visualization is written back to the backend (Phase 8.2's
    "graph is always derived, never stored" is unaffected).

## Explicit non-goals (not built)

Editing nodes/edges; AI-assisted layout or summarization; inferred causality,
confidence, centrality, or clustering; graph persistence or view-state
save/restore; a second graph data model; a general-purpose graph query
language; Neo4j/GraphQL or any other graph datastore; export (STIX/PNG/SVG);
multi-investigation merged graphs; animation/physics simulation. All remain
explicitly out of scope, matching the brief.

## Testing

`frontend/components/workspace/graph/graphAdapter.test.ts` — **25 tests**:
node/edge preservation (id, data, verbatim field pass-through), no-invention
guarantees (node/edge counts never exceed the API response) for both a
populated graph and edge cases (nodes without edges, a fully empty graph),
deterministic layout (byte-identical repeated calls; same node position
regardless of input list order), the display-only edge-label transform
(asserted distinctly from the untouched underlying `relationship_type`),
`matchesQuery` (value/type match, case-insensitivity, empty-query
matches-all), `visibleNodeIds` (no filters, type filter, severity filter
including `null`, search filter, AND-combination of multiple filters), and
`visibleEdgeIds` (both-endpoints-visible, either-endpoint-hidden,
relationship-type filter, never-invents-an-edge).

No new backend tests were needed or added — no backend code changed this
phase.

## Browser verification

Verified with real, scripted Playwright sessions (Chromium) against a live
backend + frontend dev server, across several hand-built and synthetically
generated investigations:

- A medium investigation (8 nodes / 8 edges, two findings sharing a subject,
  a malware-family and infrastructure relationship, and a correlation
  observation): graph renders with the correct node/edge counts; clicking a
  node opens the inspector with correct id/type/value/severity/source
  references; clicking an edge (using its real, non-zero-height hit target —
  some edges in the deterministic column layout are short, perfectly
  horizontal segments) shows the correct edge id/relationship/evidence
  references; search for a known entity shows a matching dropdown result and
  selecting it drives the inspector; toggling a type filter chip shows/hides
  the "Reset filters" control and updates canvas visibility; zoom-in and
  fit-view controls respond without error; the sibling Timeline section still
  expands and renders correctly alongside the new graph (no regression).
- A "solo" investigation (one node, no edges): renders the single node with
  no edges, no crash.
- An empty investigation (no attached results): shows the unchanged "No
  evidence-supported entities" message; the graph canvas is not mounted at
  all.
- A narrow (420px) viewport: the toolbar, canvas, and inspector reflow to a
  stacked layout (`flex-col` below the `lg` breakpoint) instead of overlapping
  or clipping.

Console errors across every session: none beyond a single, pre-existing,
unrelated `404` favicon-style network message already present in every prior
phase's browser verification in this project — confirmed not caused by this
phase's code.

## Performance

Checked at a larger synthetic scale (40 findings, each with one relationship
→ 80 nodes / 40 edges) generated via direct API calls: the graph rendered (80
React Flow nodes, 40 edges present in the DOM) in under 1 second after the
section's own loading state cleared, and a combined zoom + fit-view + search +
filter interaction round-trip completed in ~1 second with no visible jank.
This is comfortably above the node/edge counts a single saved investigation
in this codebase's own golden/validation corpora produces today; no
virtualization or pagination was judged necessary at this phase's intended
scale, consistent with Phase 8.2's own "no pagination... acceptable at the
intended scale" precedent.

## Known limitations

- **Deterministic column layout, not a force-directed or hierarchical one.**
  Large graphs with many nodes of the same `node_type` produce a tall single
  column rather than a space-filling arrangement. Chosen deliberately over
  physics-based layout per the brief's preference for a simple, reproducible,
  non-invented arrangement; a future phase could add an opt-in alternate
  layout without changing the underlying adapter contract.
- **No edge bundling/routing around nodes.** React Flow's default straight
  edges can visually cross unrelated nodes in a dense graph; acceptable at
  today's typical graph sizes (see Performance) and does not affect
  correctness of what's displayed.
- **No minimap.** Considered and left out as an unnecessary addition at this
  phase's typical graph sizes; `fitView` plus the existing zoom/pan controls
  are sufficient for the node/edge counts observed.
- **No keyboard-only graph navigation** beyond what React Flow provides by
  default (tab-focusable controls). A future accessibility pass could add
  arrow-key node traversal; out of scope for this phase's brief.
- **Search is client-side substring matching only**, scoped to the
  already-loaded graph — matching Phase 8.2's explicit non-goal of "no fuzzy
  or semantic search."

## Future extensions (explicitly out of scope for this phase)

Per the brief: editing, AI-assisted analysis, persistence of view state,
export, and multi-investigation graphs are not started. Natural next steps
this phase's design already accommodates without rework: an alternate
opt-in layout algorithm (the adapter's `toFlowGraph` output shape would not
need to change, only `layoutPositions`); a minimap; export-to-image; keyboard
navigation.

## Readiness review

**GO.**

- No backend changes: `backend/src/threatlens/graph/` and the
  `GET /api/v1/workspace/{id}/graph` route are byte-for-byte unmodified;
  confirmed via `git diff --stat` (backend directory absent from the diff)
  and an unchanged `graph_version`.
- No API/contract changes: the frontend consumes the exact same
  `EvidenceGraph` shape as Phase 8.2; `frontend/lib/api/workspace.ts` was not
  modified.
- No invented data: all ten evidence-integrity invariants hold by
  construction and are exercised by `graphAdapter.test.ts`'s no-invention and
  verbatim-preservation tests.
- Existing tests: full frontend suite green, **157 passed** (up from 132 —
  the delta is entirely the new `graphAdapter.test.ts`); production build
  clean.
- Manually verified end-to-end in a real browser against a live backend
  across five distinct investigations (populated, solo-node, empty, narrow
  viewport, and a larger synthetic 80-node/40-edge graph): correct rendering,
  correct inspection, correct search, correct filtering, correct
  zoom/pan/fit-view, no console errors beyond a pre-existing unrelated
  network message, no regression in the sibling Timeline section, and
  acceptable performance at the larger synthetic scale.
