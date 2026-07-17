# Phase 8.0 — Investigation Workspace Framework

## Status

Complete. Adds a workflow and persistence layer over the existing analytical
pipeline. **Not a new intelligence engine** — it stores, retrieves, filters,
and updates already-computed investigation results. It does not generate
them, and it does not modify the Reasoning, Detection, Correlation, Exposure,
or Identity engines, or the frozen `/investigate` API.

## Purpose

Every prior phase produces a result: `/investigate` returns an
`InvestigationSummary`, `/detections` returns a `DetectionPackage`, and (in a
later phase) correlation will return a `CorrelationSummary`. Until this
phase, none of that output survived past the HTTP response — closing the
browser tab lost the investigation. Phase 8.0 is the explicitly-deferred
follow-up: a save/load/list/filter layer over completed investigations, with
no authentication (single-user, self-hosted) and no database (a local
file-backed store, designed to be replaced later without touching the
service or API layer above it).

## A naming collision, disclosed up front

**"Investigation Workspace" already names an existing, shipped feature** —
`frontend/components/InvestigationWorkspace.tsx`, the per-search analyst UI
(assessment headline, findings, recommendations, provider details) that
renders **one** just-completed investigation result. It is versioned in its
own right (CHANGELOG: "Investigation Workspace v2" as of v1.1.1) and this
phase does not rename, redesign, or otherwise touch it.

This phase's brief also calls its new save/load layer "the Investigation
Workspace." Rather than quietly picking one meaning and hoping context
carries it, both are named explicitly here:

- **The existing "Investigation Workspace"** (Phase 3.x, unchanged): the live
  display component for a single, just-run investigation. Still exactly
  `components/InvestigationWorkspace.tsx`.
- **This phase's Investigation Workspace** (Phase 8.0, new): the persistence
  framework — backend `threatlens.workspace` package, `/api/v1/workspace`
  routes, and a frontend `/workspace` route tree — for saving, browsing, and
  revisiting *many* completed investigations across sessions.

To keep the two unambiguous in code (not just prose), every new file lives
under its own `workspace` directory on both sides
(`backend/src/threatlens/workspace/`, `frontend/components/workspace/`,
`frontend/app/workspace/`) rather than inside the existing
`components/investigation/` tree, and the new frontend routes are `/workspace`
and `/workspace/[id]` — distinct URLs from the existing per-search flow at
`/`. The one place the two meet is a single new
`SaveInvestigationButton`, added to the existing display component so a
completed investigation can actually reach the new persistence layer.

## Another disclosed decision: "Investigation Summary" = "Reasoning Summary"

The brief lists both "Investigation Summary" and "Reasoning Summary" as
things a saved record may contain. ThreatLens has exactly one model for a
completed investigation's deterministic reasoning output —
`threatlens.reasoning.models.InvestigationSummary`, produced by the
Investigation Intelligence Engine's `reason()`. There is no second,
independent "reasoning summary" type anywhere in the codebase. This phase
reuses that one model for both labels rather than inventing a duplicate —
consistent with the brief's own "reuse existing models wherever possible"
and "avoid duplication," which would otherwise be violated by the letter of
a different bullet a few lines above.

## Data model

`backend/src/threatlens/workspace/models.py`:

| Model | Role |
|---|---|
| `WorkspaceStatus` | `StrEnum`: `open`, `in_progress`, `closed`, `archived`. Analyst-controlled, never inferred. |
| `WorkspaceInvestigation` | The saved record: metadata envelope + up to three optional, verbatim engine outputs. |
| `SaveInvestigationRequest` | Create input — every `WorkspaceInvestigation` field except the three server-assigned ones. |
| `UpdateInvestigationRequest` | Partial-update input — every field optional; only what the caller actually sets changes. |

`WorkspaceInvestigation` fields:

```
id: UUID                                    # uuid4() — see "Identity", below
title: str
created_at: datetime
updated_at: datetime
status: WorkspaceStatus = OPEN
tags: list[str] = []
summary: str | None                         # analyst free-text note
severity: Severity | None                   # reused from threatlens.reasoning
investigation_type: EntityType              # reused from threatlens.entities.types
investigation_summary: InvestigationSummary | None   # reused from threatlens.reasoning
detection_package: DetectionPackage | None           # reused from threatlens.detection
correlation_summary: CorrelationSummary | None        # reused from threatlens.correlation
```

Every nested field is an **existing engine's own output model, imported
verbatim** — nothing here redeclares a single field of `InvestigationSummary`,
`DetectionPackage`, or `CorrelationSummary`. The workspace defines only its
own metadata envelope (`id`, `title`, `status`, `tags`, `summary`, `severity`,
`investigation_type`, timestamps) and reuses `Severity`
(`threatlens.reasoning`) and `EntityType` (`threatlens.entities.types`)
rather than declaring new closed vocabularies for either.

All three nested fields are **optional**: the workspace does not require
every downstream engine to have run before a record can be saved. In
practice, `correlation_summary` will almost always be absent — Correlation
is not yet wired into `/investigate` (Phase 7.x), so no API path exists
today that produces one from a real investigation; the field exists so a
later phase can populate it with zero model change here.

### Identity: `uuid4()`, not content-addressed

Unlike `CorrelationObservation` or `DetectionPackage`, `WorkspaceInvestigation.id`
is a random `uuid4()`, matching the existing `search_id`/`investigation_id`
convention (`/detect` and `/investigate`, both also `uuid4()`) rather than
the Detection/Correlation engines' content-addressed identity. This is a
deliberate difference, not an oversight: a saved investigation is a mutable,
analyst-owned record — title, tags, status, and severity change over its
lifetime — not a pure recomputation of deterministic engine output. Saving
identical content twice must produce two distinct records (the analyst
explicitly chose to save again), not a collision.

### Mutability: the one non-frozen model in the codebase

Every other Pydantic model in ThreatLens is `model_config = ConfigDict(frozen=True)`
— they are computed, immutable value objects. `WorkspaceInvestigation` is
the one exception: it is designed to be mutated over its lifetime (status
transitions, tag edits, title renames, re-attaching a later-generated
detection package). Every nested engine output it references remains frozen
exactly as that engine produced it; only the workspace's own envelope
changes, and always by producing a new instance (`model_copy(update=...)`),
never in-place mutation.

## Storage abstraction

`backend/src/threatlens/workspace/storage.py`:

```python
class WorkspaceStorage(ABC):
    def save(self, record: WorkspaceInvestigation) -> None: ...
    def load(self, investigation_id: UUID) -> WorkspaceInvestigation: ...
    def delete(self, investigation_id: UUID) -> None: ...
    def list_all(self) -> list[WorkspaceInvestigation]: ...
    def exists(self, investigation_id: UUID) -> bool: ...
```

`LocalFileStorage` is the only implementation this phase ships: one JSON
file per investigation (`{id}.json`) under a configurable root
(`WorkspaceSettings.storage_dir`, env `THREATLENS_WORKSPACE_DIR`, default
`data/workspace`). Writes are atomic (temp file + rename) so a crash
mid-write never corrupts an existing record. `list_all()` skips any file
that fails to parse rather than failing the whole listing — one corrupt
record should not make every other saved investigation unreachable; `load()`
(a request for that one specific id) still raises clearly on the same
corruption.

The abstract base is the seam a later phase needs: a database-backed
`WorkspaceStorage` (Postgres, SQLite, …) can replace `LocalFileStorage`
behind the exact same five-method interface, with zero change to
`WorkspaceService` or the API layer. No database is implemented in this
phase, per the brief.

## Service

`backend/src/threatlens/workspace/service.py` — `WorkspaceService`:

- `save(request, *, now=None) -> WorkspaceInvestigation` — assigns a fresh
  `uuid4()` and `created_at == updated_at == now` (or `datetime.now(UTC)`).
- `get(investigation_id) -> WorkspaceInvestigation` — raises
  `InvestigationNotFoundError` if missing.
- `update(investigation_id, request, *, now=None) -> WorkspaceInvestigation`
  — merges only the fields the caller actually set
  (`request.model_dump(exclude_unset=True)`), bumps `updated_at`, leaves
  `created_at` untouched.
- `delete(investigation_id) -> None`.
- `list(*, status=None, severity=None, investigation_type=None, tag=None, query=None) -> list[WorkspaceInvestigation]`
  — pure in-memory filtering over `storage.list_all()`, AND-combined,
  sorted most-recently-updated first. `query` is a case-insensitive
  substring match over title, summary, and tags.

`now` is an injectable parameter (mirroring `reason(entity, ti, kb, now=NOW)`
in the Reasoning Engine's own tests) so save/update timestamps are
deterministic and testable without patching the system clock.

The service contains **no investigation logic, no reasoning, no
correlation** — every value it touches is either workspace metadata or an
already-computed engine output the caller attached verbatim.

## API

`backend/src/threatlens/api/routes/workspace.py`, mounted at `/api/v1/workspace`:

| Method | Path | Behavior |
|---|---|---|
| `POST` | `/api/v1/workspace` | Save a new investigation. `201` + the full record. `422` on invalid input (blank title, missing `investigation_type`, …). |
| `GET` | `/api/v1/workspace` | List saved investigations — **metadata only** (`WorkspaceListItem`; no nested engine outputs). Query params: `status`, `severity`, `investigation_type`, `tag`, `q` — all optional, AND-combined. |
| `GET` | `/api/v1/workspace/{id}` | Load one full record, including every attached engine output. `404` if missing. |
| `PUT` | `/api/v1/workspace/{id}` | Partial update (PATCH-style merge semantics — see below). `404` if missing. |
| `DELETE` | `/api/v1/workspace/{id}` | Delete. `204` on success, `404` if missing. |

`WorkspaceListItem` (in `api/schemas.py`, alongside every other response DTO)
is a deliberate projection: exactly the "Investigation metadata" fields the
brief names for a list view (id, title, created/updated, status, tags,
summary, severity, investigation_type) — never the potentially large nested
`investigation_summary`/`detection_package`/`correlation_summary` payloads,
which only the single-record `GET /{id}` returns.

### `PUT` is a partial update, not a full replace

Strict REST convention treats `PUT` as whole-resource replacement. This API
deliberately uses PATCH-style merge semantics instead — every field on
`UpdateInvestigationRequest` is optional, and only fields present in the
request body change (an explicit `null` clears a field; an omitted field
leaves it untouched). The brief describes "Update Investigation" as a
capability, not a wire-format mandate, and simple UI actions ("change
status to Closed", "add a tag") would otherwise have to resend the entire
record, including two nested engine-output payloads, just to flip one
enum. This is a disclosed, deliberate deviation for usability — not an
oversight.

### `SaveInvestigationRequest`/`UpdateInvestigationRequest` live in the domain package, not `api/schemas.py`

Every other request/response DTO in ThreatLens lives in `api/schemas.py`.
These two are the exception: they are the workspace's own input contracts
(the fields of `WorkspaceInvestigation` minus the three server-assigned
ones), so they live in `workspace/models.py` next to the record they
describe, and `api/schemas.py` imports them the same way it already imports
every other subsystem's *output* models (`InvestigationSummary`,
`AggregatedResult`, …) rather than redeclaring their fields. `api/schemas.py`
adds only the two projections that are genuinely API-layer concerns:
`WorkspaceListItem` and `WorkspaceListResponse`.

### The one CORS fix this phase required

Manual browser verification (frontend on one origin, backend on another —
the documented `NEXT_PUBLIC_API_URL` cross-origin configuration) surfaced a
real bug: `api/app.py`'s `CORSMiddleware` allowed only `GET, POST`. Every
prior route was GET or POST, so this was never exercised; the workspace's
`PUT`/`DELETE` endpoints failed their cross-origin preflight, and the
browser silently never sent the real request. Fixed by adding `PUT, DELETE`
to `allow_methods` — a one-line, additive change with no effect on any
existing route's CORS behavior (verified: see Testing, below). This is the
only line changed in `app.py` beyond mounting the new router.

## Frontend

- **`frontend/lib/api/workspace.ts`** — typed client: `saveInvestigation`,
  `listInvestigations`, `getInvestigation`, `updateInvestigation`,
  `deleteInvestigation`. Reuses `InvestigationSummary`/`EntityType` from
  `./investigation` and `DetectionPackage` from `./detection` rather than
  redeclaring them; `CorrelationSummary` is a deliberately opaque
  `Record<string, unknown>` alias (mirrors the backend model by name only —
  no UI renders its fields yet, since Correlation isn't wired into
  `/investigate`).
- **`frontend/lib/api/client.ts`** gained `put()`/`del()` — the shared
  transport primitives had only `post()`/`get()` before this phase, since no
  prior endpoint needed PUT or DELETE.
- **`frontend/app/workspace/page.tsx`** — the saved-investigations list:
  search box, status filter, severity filter, one row per investigation
  (title, status badge, severity badge, entity type, updated date, tag
  preview, delete), and an empty state.
- **`frontend/app/workspace/[id]/page.tsx`** — the detail view: an editable
  status dropdown, tags/severity/summary display, and — reusing the
  existing, already-pure `InvestigationSummaryCard`, `RecommendationRollup`,
  and `FindingsSection` components verbatim (props-only, no internal
  fetching) — the attached `investigation_summary`, if present. A
  `detection_package`, if present, gets a compact artifact list rather than
  reusing `DetectionEngineeringCard` (which fetches its own package live on
  expand — reusing it here would silently regenerate content instead of
  displaying the saved snapshot, contradicting "the workspace consumes
  results, it does not generate them").
- **`frontend/components/workspace/SaveInvestigationButton.tsx`** — the one
  new piece wired into the existing `InvestigationWorkspace.tsx` display
  component. One click saves the current `investigation_summary` under a
  default title (`"{EntityType label}: {value}"`); the button then becomes
  a link straight to the new record's detail page. Title/tags/severity
  refinement happens afterward from the detail page — this keeps the
  addition to the existing, unmodified display component to a single new
  import and a four-line JSX block.

## Testing

`backend/tests/workspace/` (95 tests):

- **`test_models.py`** — defaults, validation (blank/oversized title and
  summary), the deliberate non-frozen behavior, JSON round-tripping,
  `exclude_unset` partial-update semantics including explicit-null-clears.
- **`test_storage.py`** — `LocalFileStorage` CRUD, atomic writes (no
  leftover `.tmp` file), corrupt-file resilience in `list_all` vs. a clear
  error from `load`, and cross-instance persistence (a second `LocalFileStorage`
  over the same root sees what the first wrote) — all against pytest's
  `tmp_path`, never the real filesystem.
- **`test_service.py`** — save/get/update/delete, deterministic `now`
  injection, and every filter (`status`, `severity`, `investigation_type`,
  `tag`, `query`) individually and combined with AND, plus sort order.
- **`test_api.py`** — the full HTTP contract: `201`/`200`/`404`/`422` across
  all five endpoints, the list-vs-detail projection difference, and that an
  `investigation_summary` from a real `/investigate` call round-trips
  byte-for-byte through save → load.
- **`test_no_regression.py`** — makes the readiness review's "no engine/API
  changes" claim a checked fact: every pre-Phase-8.0 route still resolves
  (via the generated OpenAPI schema, not FastAPI's internal `Route`
  representation, which changed shape between FastAPI versions), engine
  version constants are unchanged, `/investigate`/`/detect`/`/correlation`/
  `/detections`/`/exposure`/`/identity`/`/health` all still behave as
  before, and — the CORS fix, above — a real cross-origin preflight for
  `PUT`/`DELETE`/`POST` succeeds, tested via `TestClient(app).options(...)`
  with `Origin`/`Access-Control-Request-Method` headers rather than a
  same-origin call that would never have caught the original bug.

Frontend: this codebase's existing Vitest suite tests `lib/*.ts` pure/API
functions only (no component-rendering tests anywhere — `vitest.config.ts`
runs `environment: "node"`, not jsdom). Phase 8.0 follows the same
convention: `saveInvestigation`/`listInvestigations`/`getInvestigation`/
`updateInvestigation`/`deleteInvestigation` are tested in
`frontend/lib/api.test.ts` (the established single file covering the whole
`lib/api/` barrel), 18 new tests. The new UI (list page, detail page, save
button) was verified with a real, scripted browser session (Playwright,
production build) exercising the full golden path — search → save →
list → filter (status/severity/search, including empty-result states) →
detail → status change → delete — against a live backend, which is also
how the cross-origin CORS bug above was actually found.

Full suite after this phase: **2,496 backend tests passed, 1 skipped** (was
2,493). Ruff and mypy (`--strict`) clean across 178 source files (was 171).
Frontend: 122 Vitest tests passed (was 104); production build clean,
including the two new routes (`/workspace` static, `/workspace/[id]`
server-rendered on demand).

## Known limitations

- **No authentication, single-user only**, as specified. The storage root
  has no access control beyond filesystem permissions.
- **No database.** `LocalFileStorage` does not scale to concurrent writers
  or large record counts gracefully — acceptable for a self-hosted,
  single-user deployment; the `WorkspaceStorage` interface is the seam for
  a later database-backed implementation.
- **`correlation_summary` will almost always be absent** in real usage: no
  API path exists today that produces a `CorrelationSummary` from a real
  investigation (Correlation is not wired into `/investigate` — Phase
  7.2+). The field and its frontend type exist so a future phase can
  populate it with no model change here.
- **No bulk operations** (bulk delete, bulk tag, export) — out of scope for
  this phase; not requested by the brief.
- **No pagination on `GET /workspace`.** Acceptable for the intended scale
  (single user, local storage); revisit if a later phase adds multi-user or
  large-volume usage.
- **The detail page's `detection_package`/`correlation_summary` sections are
  intentionally minimal** (a compact list, not the full interactive
  `DetectionEngineeringCard` experience) — reusing that card would trigger a
  live re-generation call, contradicting "the workspace consumes results, it
  does not generate them."

## Future expansion (explicitly out of scope for this phase)

Per the brief: Timeline Engine, Evidence Graph, Case Management, RBAC,
STIX/TAXII, SOAR, and any other enterprise feature are not started. A
database-backed `WorkspaceStorage`, bulk operations, export, and wiring
Correlation into `/investigate` (so `correlation_summary` is ever populated
in practice) are natural next steps but are not part of Phase 8.0.

## Readiness review

**GO.**

- No engine changes: Reasoning, Detection, Correlation, Exposure, and
  Identity are byte-for-byte unmodified (engine version constants
  unchanged; verified by `test_no_regression.py`).
- No existing API changes beyond one additive CORS fix (`GET, POST` →
  `GET, POST, PUT, DELETE`), required for the *new* PUT/DELETE endpoints
  and verified to leave every existing route's behavior unchanged.
- Existing tests: full backend suite green, **2,496 passed / 1 skipped**
  (up from 2,493 — the delta is entirely new workspace + regression tests).
  Frontend: 122 Vitest tests passed (up from 104), production build clean.
- The workspace strictly consumes existing outputs (`InvestigationSummary`,
  `DetectionPackage`, and — once populated by a later phase —
  `CorrelationSummary`) and never recomputes them.
- Manually verified end-to-end in a real browser against a live backend:
  search → save → list → filter → detail → status update → delete, which
  is also how the one real bug found during this phase (the CORS gap) was
  caught and fixed before landing.
