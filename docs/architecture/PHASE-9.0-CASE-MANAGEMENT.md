# Phase 9.0 — Case Management Framework

## Status

Complete. Introduces a new, independent subsystem — Case Management — that
operates **above** the Workspace platform frozen in Phase 8.5. **Not a
Workspace change**: every Workspace/Timeline/Graph/Report/Export contract,
route, storage location, and behavior is untouched. Case Management reads
from Workspace (to confirm a linked investigation exists) and never writes
to it, recomputes it, or duplicates its content.

## Purpose

Phases 8.0–8.5 gave ThreatLens a persistence layer for individual completed
investigations (`WorkspaceInvestigation`) and read-only derived views over
one investigation at a time (Timeline, Evidence Graph, Report/Export). None
of that gives an analyst a place to track *operational* work that spans
**multiple** investigations — a phishing campaign touching five separate
IOC investigations, say, that needs one shared status, priority, owner, and
running set of notes. Phase 9.0 adds exactly that: a `Case` is an
operational object; a `WorkspaceInvestigation` remains an immutable
analytical artifact. Cases organize investigations by reference — they do
not replace, extend, or duplicate them.

```
Workspace Investigation(s)
        │
        ▼
      Case
```

Never the other direction: a `Case` never appears inside a
`WorkspaceInvestigation`, and Workspace's own models, storage, and API are
entirely unaware Case Management exists.

## Architecture

New package, mirroring `threatlens.workspace`'s own architecture exactly
(models → storage → service → API), with one deliberate placement
difference explained below:

```
backend/src/threatlens/cases/
    __init__.py     # public exports
    models.py       # Case, CaseStatus, CasePriority, CaseNote (domain)
    schemas.py       # CreateCaseRequest, UpdateCaseRequest, LinkWorkspaceRequest,
                      # AddNoteRequest, CaseListResponse (request/response DTOs)
    storage.py        # CaseStorage (ABC) + LocalFileStorage
    service.py         # CaseService — CRUD, filtering, linking, notes,
                        # status-transition validation
    exceptions.py        # CaseError, CaseNotFoundError, CaseStorageError,
                          # InvalidStatusTransitionError
    config.py              # CaseSettings.from_env() (THREATLENS_CASES_DIR)

backend/src/threatlens/api/routes/cases.py   # thin FastAPI router
```

**Deliberate deviation from the brief's suggested layout**: routes live in
`api/routes/cases.py`, not `cases/api.py`. Every other subsystem in this
codebase (`workspace`, `timeline`, `graph`, `reporting`, `correlation`, …)
puts its routes in `api/routes/<name>.py`, registered from `api/app.py`.
Putting Case Management's routes inside its own package would make it the
one architectural exception in the codebase for no functional benefit —
consistency with the established pattern was judged more valuable than
following the brief's suggested filename literally.

**Dependency direction**: `cases/service.py` takes a
`threatlens.workspace.service.WorkspaceService` as a constructor argument
and calls exactly one method on it — `WorkspaceService.get(workspace_id)` —
to confirm a linked investigation exists before accepting a link. This is
the same "verify via the canonical service, never re-implement lookup"
pattern `ReportService` already uses for `TimelineService`/`GraphService`.
Workspace has no equivalent import of `cases` anywhere — the dependency is
strictly one-directional.

**Lazy singleton construction**: `api/routes/cases.py`'s
`get_case_service()` mirrors `get_workspace_service()`'s exact lazy-build,
success-only-memoized pattern (see the Vercel production fix, Phase 8.x):
`LocalFileStorage.__init__` performs disk I/O (`mkdir`), so building the
service eagerly at module-import time would risk taking down the entire
app's import on a read-only or misconfigured deployment filesystem — not
just the case routes. `get_case_service()` composes the already-lazily-built
`get_workspace_service()` singleton on its own first call.

## The `Case` model

```python
class Case(BaseModel):
    id: UUID
    title: str
    description: str | None
    status: CaseStatus = CaseStatus.OPEN
    priority: CasePriority = CasePriority.MEDIUM
    created_at: datetime
    updated_at: datetime
    owner: str | None
    tags: list[str]
    linked_workspace_ids: list[UUID]
    notes: list[CaseNote]
    metadata: dict[str, JsonValue]
```

`Case` is **not frozen** — mirroring
`WorkspaceInvestigation` exactly, not the frozen pure-projection models
(`Timeline`, `EvidenceGraph`, `InvestigationReport`) the Workspace platform
also produces. A case is an operational record mutated over its lifetime;
`id` is a random `uuid4()`, not content-addressed, matching the same
"two saves of identical content are two distinct records" rationale
`WorkspaceInvestigation` documents. `linked_workspace_ids` holds only ids —
never a copy of the referenced investigation's title, type, or any other
field. `metadata` is a deliberately open, unopinionated
`dict[str, JsonValue]` extension point that no current code path reads —
present for future callers, not a hidden feature.

`CaseNote` is **frozen** and append-only:

```python
class CaseNote(BaseModel):
    author: str
    timestamp: datetime
    content: str
```

No editing, no deletion — the brief is explicit on this — and no markdown
or other rendering of `content`; it is stored and returned as plain text
verbatim.

## Status lifecycle

```python
class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
```

Transitions are validated against a fixed graph in `cases/service.py`:

```
OPEN  <──────────────┐
  │                   │
  ▼                   │
IN_PROGRESS ─────► RESOLVED
  │  ▲                │
  │  └────────────────┤
  ▼                    ▼
CLOSED ─────────────► (only exit: reopen to OPEN)
```

Concretely: `OPEN → {IN_PROGRESS, CLOSED}`; `IN_PROGRESS → {OPEN, RESOLVED,
CLOSED}`; `RESOLVED → {IN_PROGRESS, CLOSED}`; `CLOSED → {OPEN}` only —
closing forces an explicit re-triage through `OPEN` rather than jumping
straight back into `IN_PROGRESS`/`RESOLVED`. A status "changing" to its own
current value is never treated as a transition (always a harmless no-op,
never checked against the graph). An invalid transition raises
`InvalidStatusTransitionError`, mapped to HTTP `409 Conflict` — distinct
from `404`/`422` — and leaves the stored case completely unchanged. This is
a deliberate design decision, not something the brief specified in detail;
it was chosen to be the smallest state machine that supports normal
triage → work → resolve → close flow plus reopening, without inventing
transitions nothing in the brief asked for.

## Priority

```python
class CasePriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

Purely an analyst judgment call — unlike
`threatlens.reasoning.models.Severity`, which the Reasoning Engine computes
from evidence, there is no analytical basis to derive a case's priority
from, so none is attempted. Freely settable at creation and via update; no
transition restrictions (unlike status).

## Relationships

One case can reference **many** Workspace investigations, and one
investigation can be referenced by **many** cases — a genuine many-to-many
relationship, never enforced as one-to-one. `link_workspace()`/
`unlink_workspace()` are both idempotent: linking an already-linked id, or
unlinking an id that isn't currently linked, is a no-op (returns the case
unchanged, does not bump `updated_at`, never errors). Linking validates
that the target investigation exists via `WorkspaceService.get()`
(propagating `InvestigationNotFoundError` → `404`); unlinking performs no
such check, since removing a reference is always safe regardless of
whether the referenced record still exists.

## Storage

Reuses the exact same approach as Workspace's own storage — the brief is
explicit: "Do NOT redesign storage." `CaseStorage` (an `ABC`) and
`LocalFileStorage` (its only implementation) are a line-for-line mirror of
`threatlens.workspace.storage`'s own `WorkspaceStorage`/`LocalFileStorage`:
one JSON file per record (`{id}.json`), atomic writes (temp file + rename),
`OSError` wrapped in the domain's own `CaseStorageError`, corrupt files
skipped (not fatal) during `list_all()` but still raised on a direct
`load()`.

Cases persist **independently** of Workspace: a separate root directory
(`data/cases` by default, overridable via `THREATLENS_CASES_DIR`, mirroring
`THREATLENS_WORKSPACE_DIR` exactly), never the same directory, never a
shared file. Deleting a case never touches any linked investigation's file;
deleting or corrupting a Workspace investigation's file never affects a
case's own stored record (only `link_workspace()`'s existence check, made
at link time, would be affected — an already-linked id that later becomes
unreachable simply stays in `linked_workspace_ids` un-validated until the
next explicit link attempt).

## API

| Endpoint | Method | Success | Errors |
|---|---|---|---|
| `/api/v1/cases` | POST | 201, `Case` | 422 |
| `/api/v1/cases` | GET | 200, `CaseListResponse` | — |
| `/api/v1/cases/{id}` | GET | 200, `Case` | 404, 422 (bad UUID) |
| `/api/v1/cases/{id}` | PATCH | 200, `Case` | 404, 409 (bad transition), 422 |
| `/api/v1/cases/{id}` | DELETE | 204 | 404 |
| `/api/v1/cases/{id}/workspace` | POST | 200, `Case` | 404 (case or investigation) |
| `/api/v1/cases/{id}/workspace/{workspace_id}` | DELETE | 200, `Case` | 404 (case) |
| `/api/v1/cases/{id}/notes` | POST | 201, `Case` | 404, 422 |

Notes on shape, each a deliberate choice:

- **`PATCH`, not `PUT`.** Workspace's own update endpoint is `PUT` used as a
  partial update — documented in Phase 8.0's own architecture doc as a
  non-standard but deliberate choice made before this convention was
  reconsidered. The brief specifies `PATCH` for Case Management, which is
  the semantically correct verb for a partial update, so this phase uses it
  without needing to carry Workspace's earlier quirk forward.
- **Link/unlink/add-note all return the updated `Case`, not `204`.** Unlike
  deleting the whole case (which stops existing, so `204` is correct),
  these three actions leave the case existing in a new state the caller
  almost always wants immediately, without a second round-trip fetch.
- **`GET /api/v1/cases` returns full `Case` records**, not a slimmed
  list-item projection. `WorkspaceListResponse` deliberately omits its
  three nested engine-output payloads (`investigation_summary`,
  `detection_package`, `correlation_summary`) because those can be large.
  A `Case` has no equivalent heavy payload — its largest fields are short
  lists of ids and short notes — so there is nothing worth slimming, and a
  parallel `CaseListItem` model would only duplicate `Case` for no benefit.
- **List filters**: `status`, `priority`, `tag`, `owner` (exact match), and
  `title` (case-insensitive substring). No full-text indexing, no ranking,
  no AI — a pure in-memory filter over already-persisted records, mirroring
  `WorkspaceService.list()`'s own filtering exactly.

## Frontend

Two new routes, mirroring the Workspace list/detail split:

- **`/cases`** — search (title substring) + status/priority/owner/tag
  filters, a list of case rows (status/priority badges, owner, linked/note
  counts, tags), and an inline "+ New Case" creation form.
- **`/cases/[id]`** — status and priority editable via `<select>` (mirrors
  the Workspace detail page's own status-select pattern exactly); an
  "Edit" toggle revealing a small form for title/description/owner/tags;
  a Linked Investigations section (each row lazily fetches the referenced
  investigation's title/type via the existing, unmodified
  `getInvestigation()` — pure read reuse, never a duplicate model) with an
  "Unlink" action per row and a "paste a Workspace investigation id, click
  Link" control; a Notes section (author/timestamp/content list, oldest
  first) with an "add a note" form.

No changes to any existing Workspace page. The brief's "Do NOT redesign
Workspace UI" is honored by construction — Case Management's frontend adds
two new files and touches only the shared `lib/api/client.ts` (a new
`patch()` primitive, a new `delWithBody()` primitive, and one bug fix
described below) and the `lib/api/index.ts` barrel.

**`client.ts` fix, discovered by this phase's own browser verification**:
`post()`'s error-mapping never special-cased HTTP `404` — only `422` — while
`put()`/`patch()`/`del()` all already map `404` to a friendly `"Not found."`
message. This asymmetry existed because no pre-existing `POST` endpoint
could genuinely 404 (`saveInvestigation`, `detect`, etc. all create or are
stateless). Case Management's `linkWorkspaceToCase`/`addCaseNote` are the
first `POST` endpoints that legitimately can — linking a nonexistent
investigation, or noting a deleted case — so this phase adds the missing
`404` case to `post()`, matching the other three primitives exactly. Not a
Workspace change: `client.ts` is shared transport, and every existing
`post()`-based test (`saveInvestigation`, `detect`, …) only asserts
`instanceof ApiError`, never an exact 404 message, so nothing regressed.

## Compatibility

Verified, not merely assumed: Workspace's own no-regression suite
(`tests/workspace/test_no_regression.py`) still passes unmodified, and a
new `tests/cases/test_no_regression.py` proves every pre-Phase-9.0 route
(including every Workspace/Timeline/Graph/Export route) is still registered
with the same HTTP methods, every existing engine/framework version
constant is unchanged, and the CORS preflight for Workspace's existing
`PUT` still succeeds alongside Case Management's new `PATCH`.

## Testing

159 new backend tests (`backend/tests/cases/`): models (defaults,
validation, frozen `CaseNote`), storage (mirroring
`tests/workspace/test_storage.py`'s exact scenarios), service (creation,
every allowed and disallowed status transition — parametrized, not
hand-duplicated — priority, filtering combinations, linking against a real
`WorkspaceService` collaborator including the many-to-many and idempotency
guarantees, notes ordering/immutability), API contract (every endpoint's
success/error shape, a full-lifecycle walk exercising all eight endpoints
in sequence), and the no-regression suite above. 24 new frontend tests
(`lib/api.test.ts`, extending the existing single-file-per-`lib/api/`-
directory convention). No test mocks `WorkspaceService` — every linking
test uses a real `WorkspaceService`/`LocalFileStorage` pair, matching this
codebase's established preference for real collaborators over mocks
wherever they're this cheap to construct.

Browser-verified end-to-end against a live backend: create → filter (title/
found and not-found cases) → open detail → change priority → valid status
transition → an *invalid* transition rejected with `409` (verified via a
direct API call, since the UI's `<select>` can only ever request states a
real analyst could pick) → edit metadata (description/owner/tags) → link a
real investigation → confirm it renders correctly → attempt to link a
nonexistent investigation (confirms the `404`/"Not found." error banner) →
add a note → unlink → confirm the underlying investigation is untouched →
`resolved → closed` → delete the case → confirm removal. 27/27 checks
passed across three consecutive runs.

Two script-side false positives were found and fixed *in the verification
script*, not the application, during this process — both worth recording
since they will recur for any future browser check of a form with a
`<textarea>`: a still-filled `<textarea>`'s typed value satisfies a plain
Playwright `text=` selector even before the surrounding form's submit
request completes (unlike `<input>`, empirically confirmed not to have this
behavior), and `page.click("text=Link")` matches the "Link**ed**
Investigations" heading's substring before the actual "Link" button,
silently clicking an inert element. Both were root-caused with direct
network-response logging before concluding "test bug, not app bug" — never
assumed.

## Known limitations

- **No enforcement that a case's linked investigations share anything** —
  entity type, time window, or otherwise. Cases organize by analyst
  judgment; the platform never infers a case's boundary.
- **`metadata` has no defined schema or consumer.** It exists as an
  extension seam only.
- **No audit trail of who changed what, when** — `updated_at` records that
  *something* changed, not what. Notes are the only append-only history
  this phase provides.
- **No case-level export/report**, unlike Workspace's own
  `GET .../export`. Explicitly out of scope for this phase (not listed in
  the brief's endpoint set); see Future Extension Points.

## Future extension points

- **A case-level report/export**, analogous to Phase 8.4's
  `InvestigationReport`, composing the case's own metadata with each
  linked investigation's existing `WorkspaceInvestigation`/`Timeline`/
  `EvidenceGraph` — a natural, additive follow-up that would reuse
  `ReportService` per linked investigation rather than inventing new
  derivation logic.
- **Case-level tags/search improvements** (saved filters, sort order) —
  additive to `CaseService.list()`'s existing filter parameters.
- Everything in the brief's Explicit Non-Goals (SOAR, detection generation,
  automation, notifications, RBAC, authentication, comments, file
  uploads/attachments, evidence editing, collaboration, dashboards,
  metrics, AI, IOC collections) remains unstarted, by design.
