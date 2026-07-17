# Phase 9.1 — Intelligence Collections Framework

## Status

Complete. Introduces a new, independent subsystem — Intelligence Collections
— that sits alongside Case Management (Phase 9.0) above the Workspace
platform (frozen at Phase 8.5). **Not a Workspace or Case Management
change**: every Workspace/Timeline/Graph/Report/Export and every Case
contract, route, storage location, and behavior is untouched. Collections
read from both Workspace and Case Management (to confirm a linked record
exists) and never write to, recompute, or duplicate either's content.

## Purpose

Phase 9.0 gave analysts a way to organize *operational work* across
investigations (a `Case`). Neither Workspace nor Case Management gives an
analyst a place to build a *reusable intelligence asset* — a named,
standing set of indicators like "Silver Fox Campaign", "APT29
Infrastructure", "ClickFix Infrastructure", "QakBot Infrastructure",
"Internal Blocklist", or "Threat Hunt IOC Pack" — that outlives any single
case or investigation and can be referenced from many of them. Phase 9.1
adds exactly that: a `Collection` is a reusable, analyst-curated container
of threat intelligence. It is explicitly **not** an analytical engine (it
detects, scores, and enriches nothing), **not** a `Case` (it has no status,
priority, or lifecycle), and **not** a `Workspace` (it holds no
investigation output) — a `Collection` is a reusable intelligence asset
that *references* Workspace investigations and Cases by id, never copying
or replacing either.

```
Workspace Investigation(s)  ──┐
                                ├──►  Case  ──►  Collection
                                │
                                └────────────────►  Collection
```

The `Workspace → Case → Collection` hierarchy above is **conceptual, not
enforced**: a `Collection` may reference Workspace investigations directly
(without going through a case) and/or Cases directly, in any combination,
including zero of either. Never the other direction: neither a
`WorkspaceInvestigation` nor a `Case` has any notion that a `Collection`
exists.

## Architecture

New package, mirroring `threatlens.cases`'s own architecture (itself a
mirror of `threatlens.workspace`): models → storage → service → API, plus
one small, self-contained module the other two subsystems didn't need.

```
backend/src/threatlens/collections/
    __init__.py     # public exports
    models.py       # Collection, Indicator, IndicatorType, CollectionSource (domain)
    normalize.py    # normalize_indicator_value() — dedup identity, pure function
    schemas.py      # Create/UpdateCollectionRequest, Add/RemoveIndicatorRequest,
                    # LinkWorkspaceRequest, LinkCaseRequest, CollectionListItem,
                    # CollectionListResponse (request/response DTOs)
    storage.py      # CollectionStorage (ABC) + LocalFileStorage
    service.py      # CollectionService — CRUD, filtering, indicator
                    # dedup/merge, linking
    exceptions.py   # CollectionError, CollectionNotFoundError, CollectionStorageError
    config.py       # CollectionSettings.from_env() (THREATLENS_COLLECTIONS_DIR)

backend/src/threatlens/api/routes/collections.py   # thin FastAPI router
```

**`normalize.py` is a deliberate addition beyond the brief's suggested file
list.** Deduplication identity — `(type, normalized_value)` — is real,
non-trivial, per-type logic (canonicalizing an IP, lowercasing a domain,
lowercasing a URL's scheme/host while preserving its case-sensitive path,
uppercasing a CVE/ATT&CK id) that doesn't belong in `models.py` (which, in
every subsystem in this codebase, is pure data shape with zero functions)
and is independently unit-testable. It is the one genuinely new modeling
problem this phase introduces; neither Workspace nor Cases needed anything
like it.

**Test directory naming note**: the backend package is named
`threatlens.collections`, exactly as specified. Its tests, however, live at
`backend/tests/intel_collections/`, not `backend/tests/collections/` — the
name every other subsystem's test directory would suggest by pattern. This
repository's `backend/tests/` root has no `__init__.py`, so pytest's default
import resolution walks up from a test file only as far as the nearest
directory lacking one, and inserts *that* directory onto `sys.path`; for
`tests/cases/`, that makes `cases` (with no stdlib module of that name) the
resolved top-level import name. For a directory literally named
`collections`, the same mechanism resolves to the **Python standard
library's own `collections` package** — confirmed empirically before writing
any test file (a throwaway `tests/collections/test_spike.py` failed
collection with `ModuleNotFoundError: No module named 'collections.test_spike'`,
proving the stdlib module wins the naming collision). The *source* package
itself is unaffected by this — `threatlens.collections` is only ever
reachable via its full dotted path, never as a bare top-level import — so
only the test directory needed a different name.

**Dependency direction**: `collections/service.py`'s `CollectionService`
takes both a `threatlens.workspace.service.WorkspaceService` and a
`threatlens.cases.service.CaseService` as constructor arguments, calling
exactly one method on each — `WorkspaceService.get(workspace_id)` and
`CaseService.get(case_id)` — to confirm a linked record exists before
accepting a link. Same "verify via the canonical service, never re-implement
lookup" pattern `CaseService` already uses for `WorkspaceService`, and
`ReportService` for `TimelineService`/`GraphService`. Neither Workspace nor
Cases imports anything from `collections` — the dependency is strictly
one-directional, and `api/routes/collections.py` composes the
already-lazily-built `get_workspace_service()`/`get_case_service()`
singletons on its own first call, mirroring `get_case_service()`'s own
lazy-build, success-only-memoized pattern exactly (see Phase 8.x's Vercel
production fix for why: `LocalFileStorage.__init__` performs disk I/O, so
eager module-level construction risks the entire app's import on a
read-only or misconfigured deployment filesystem).

## The `Collection` and `Indicator` models

```python
class Collection(BaseModel):
    id: UUID
    name: str
    description: str | None
    category: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    source: CollectionSource = CollectionSource.MANUAL
    linked_case_ids: list[UUID]
    linked_workspace_ids: list[UUID]
    metadata: dict[str, JsonValue]
    indicators: list[Indicator]
```

`Collection` is **not frozen** — an operational, analyst-curated record
mutated over its lifetime, matching `Case`'s (and `WorkspaceInvestigation`'s)
posture, not the frozen pure-projection models (`Timeline`, `EvidenceGraph`,
`InvestigationReport`) the Workspace platform separately produces. `id` is a
random `uuid4()`, not content-addressed — two collections with identical
content are two distinct records. `category` is a deliberately free-text,
analyst-assigned field, not a closed enum: unlike `CaseStatus`/`CasePriority`
(which the brief enumerated explicitly), the brief gives no fixed taxonomy
for collection categories, and the example collection names span wildly
different organizing principles (a campaign, a threat actor, a malware
family, an operational blocklist) that don't fit one fixed set — `category`
mirrors `Case.owner`'s own free-text, filterable posture.

```python
class CollectionSource(StrEnum):
    MANUAL = "manual"
    WORKSPACE = "workspace"
    CASE = "case"
```

`source` **is** a closed enum, unlike `category` — the brief explicitly
names exactly three ways a collection can originate ("Collections may be
created manually, from Workspace, from Case"). It is pure provenance
metadata, set once at creation and never editable afterward
(`UpdateCollectionRequest` has no `source` field): choosing `WORKSPACE` or
`CASE` does not itself pull in any data — "Do NOT automatically extract
intelligence. Extraction will come later" (phase brief) — an analyst who
builds a collection while looking at an investigation or a case still adds
every indicator explicitly.

```python
class Indicator(BaseModel):
    type: IndicatorType
    value: str
    first_seen: datetime | None
    last_seen: datetime | None
    confidence: int | None    # 0-100, STIX-style confidence scale
    tags: list[str]
    source: str | None
    notes: str | None
```

An `Indicator` has **no id field** — its identity for every purpose
(deduplication, removal) is `(type, normalize_indicator_value(type, value))`
(see Normalization below), computed on demand rather than stored. It is
**not frozen**, unlike `CaseNote` (append-only, "no editing, no deletion" per
the Case Management brief): re-adding an indicator whose identity already
exists in a collection **merges** into the existing record rather than being
rejected or creating a duplicate (see `CollectionService.add_indicator`),
so an indicator's fields legitimately change over its lifetime as new
sightings arrive.

```python
class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    SHA1 = "sha1"
    SHA256 = "sha256"
    MD5 = "md5"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"
    MITRE_SOFTWARE = "mitre_software"
    MITRE_GROUP = "mitre_group"
    REGISTRY = "registry"
    MUTEX = "mutex"
    FILENAME = "filename"
    PROCESS = "process"
    CERTIFICATE = "certificate"
```

The 18 types the brief enumerates. Deliberately **not** the same enum as the
Universal Entity Detection Engine's `EntityType`
(`threatlens.entities.types.EntityType`): that engine *classifies* freeform
search input, producing a type with a confidence and a validation status —
an `Indicator` is always already typed by the analyst (or by whatever
upstream Workspace/Case data it was drawn from) at the moment it is added,
so no classification ever happens inside Collections. The two enums are
intentionally independent and are not interchangeable.

## Normalization (indicator deduplication identity)

`normalize_indicator_value(indicator_type, value) -> str` is a pure,
deterministic string transform — no network, no validation-as-rejection:

| Types | Canonical form |
|---|---|
| `IPV4`, `IPV6` | `ipaddress.ip_address(value).compressed` (canonicalizes IPv6 zero-compression and equivalent forms); falls back to a lowercase strip if the value doesn't parse |
| `URL` | scheme and host lowercased via `urlsplit`/`urlunsplit`; path/query/fragment casing preserved (paths are case-sensitive per RFC 3986, unlike host) |
| `CVE`, `MITRE_TECHNIQUE`, `MITRE_SOFTWARE`, `MITRE_GROUP` | uppercased (`CVE-2024-3094`, `T1059.001`, `S0154`, `G0016` are the published canonical casings) |
| every other type (`DOMAIN`, `HOSTNAME`, `EMAIL`, hashes, `REGISTRY`, `MUTEX`, `FILENAME`, `PROCESS`, `CERTIFICATE`) | lowercased |

Every normalizer strips surrounding whitespace first. **Malformed input never
raises** — an unparseable IP, for example, falls back to a simple
lowercase-strip rather than being rejected, because Collections "store only
explicitly provided intelligence" (phase brief's Determinism section):
rejecting malformed input is the Search/detection engine's job, not this
one's. This was confirmed to be the correct behavior, not an oversight, when
Python's `ipaddress` module was found to reject IPv4 addresses with leading
zeros (`001.001.001.001`) as a deliberate CVE-2021-29921 hardening measure —
the fallback path exists precisely for cases like this.

## Indicator deduplication and merge

Adding an indicator whose `(type, normalized_value)` already exists in the
collection **merges** into the existing record rather than creating a
duplicate or being silently rejected — the one piece of genuine business
logic this subsystem owns, structurally analogous to Case Management owning
status-transition validation as *its* one piece of real domain logic. The
merge rule, in `CollectionService._merge_indicator` (module-level helper):

- `first_seen` / `last_seen`: widen to the earliest / latest of the two
  non-null values (a collection's indicator should reflect its full observed
  range, not just the most recent sighting).
- `tags`: union, insertion order, deduplicated.
- `confidence`, `source`, `notes`: the incoming (newest) value wins when
  provided; otherwise the existing value is kept.
- `value` (the raw, analyst-typed string): left untouched. Both spellings
  are, by definition, the same normalized identity, so there is no
  principled reason to prefer one over the other, and keeping the
  first-added spelling avoids the displayed value jittering on every re-add.

This was a genuine design decision the brief left implicit ("Indicators must
be deduplicated" doesn't specify what happens to the other fields on a
second add). The alternative — silently dropping the second add entirely —
was rejected because it would lose real information (a wider seen-range, new
tags) that a re-add legitimately carries.

Removal (`CollectionService.remove_indicator`) matches the same
`(type, normalized_value)` identity and is idempotent: removing an identity
that isn't present is a no-op, mirroring
`CaseService.unlink_workspace`'s own idempotency guarantee.

## Relationships

A collection may reference **zero or more** Workspace investigations and
**zero or more** Cases — many-to-many in both directions, exactly like
`Case.linked_workspace_ids`, never enforced as one-to-one. `link_workspace()`
and `link_case()` are both idempotent (linking an already-linked id is a
no-op, does not bump `updated_at`, never errors) and both validate the
target exists first (`WorkspaceService.get()` / `CaseService.get()`,
propagating `InvestigationNotFoundError`/`CaseNotFoundError` → `404`).

**No unlink endpoint exists for either relationship** — a deliberate
adherence to the brief's exact API list, not an oversight. Unlike Case
Management (which has both `POST .../workspace` and
`DELETE .../workspace/{workspace_id}`), the Phase 9.1 brief's endpoint list
and Frontend capability list both name only "link Workspace"/"link Case",
never "unlink" — so only the link direction is implemented. See Future
Extension Points.

## Storage

Reuses the exact same approach as Workspace's and Cases' own storage —
independent, `CollectionStorage` (an `ABC`) plus `LocalFileStorage` (its
only implementation), a line-for-line mirror of
`threatlens.cases.storage`/`threatlens.workspace.storage`: one JSON file per
record (`{id}.json`), atomic writes (temp file + rename), `OSError` wrapped
in `CollectionStorageError`, corrupt files skipped (not fatal) during
`list_all()` but still raised on a direct `load()`.

Collections persist in their own root directory — `data/collections` by
default, overridable via `THREATLENS_COLLECTIONS_DIR`, mirroring
`THREATLENS_CASES_DIR`/`THREATLENS_WORKSPACE_DIR` exactly. No two of the
three storage roots ever overlap or share a file. Deleting a collection
never touches any linked investigation's or case's file; deleting a
Workspace investigation or a Case never touches a collection's own stored
record (only `link_workspace()`/`link_case()`'s existence check, made at
link time, would be affected).

## API

| Endpoint | Method | Success | Errors |
|---|---|---|---|
| `/api/v1/collections` | POST | 201, `Collection` | 422 |
| `/api/v1/collections` | GET | 200, `CollectionListResponse` | — |
| `/api/v1/collections/search` | GET | 200, `CollectionListResponse` | — |
| `/api/v1/collections/{id}` | GET | 200, `Collection` | 404, 422 (bad UUID) |
| `/api/v1/collections/{id}` | PATCH | 200, `Collection` | 404, 422 |
| `/api/v1/collections/{id}` | DELETE | 204 | 404 |
| `/api/v1/collections/{id}/indicator` | POST | 201, `Collection` | 404, 422 |
| `/api/v1/collections/{id}/indicator` | DELETE | 200, `Collection` | 404 |
| `/api/v1/collections/{id}/workspace` | POST | 200, `Collection` | 404 (collection or investigation) |
| `/api/v1/collections/{id}/case` | POST | 200, `Collection` | 404 (collection or case) |

Notes on shape, each a deliberate choice:

- **Two GET-list endpoints, not one.** The brief lists both
  `GET /api/v1/collections` and `GET /api/v1/collections/search` explicitly,
  unlike Case Management's single `GET /cases` with query-param filters. This
  phase honors that literally: plain `GET /collections` is an unfiltered
  browse-everything endpoint; `GET /collections/search` accepts six optional
  filters (`name` substring, `category`, `indicator_type`, `tag`,
  `linked_case_id`, `linked_workspace_id`), all AND-combined. Both routes
  call the same `CollectionService.list()` method (filters default to
  `None` = no filter), so there is exactly one filtering implementation
  behind two thin, purpose-named routes — no duplicated logic.
- **Route registration order matters and is guarded by a test.**
  `GET /api/v1/collections/search` is registered *before*
  `GET /api/v1/collections/{collection_id}` in `api/routes/collections.py`.
  Starlette resolves ambiguous same-method paths in registration order; had
  the `{collection_id}` route been registered first, a request to
  `/collections/search` would be captured by it (with `collection_id="search"`),
  fail UUID coercion, and return `422` — never reaching the search handler at
  all. `tests/intel_collections/test_api.py::TestSearchCollectionsRouteOrdering`
  exercises this directly.
- **`GET /api/v1/collections` and `.../search` return `CollectionListItem`
  rows, not full `Collection` records** — the one point where this phase's
  list-response shape diverges from Case Management's. `Case`'s largest
  fields (`notes`, `linked_workspace_ids`) stay small in practice, so Cases
  returns full records from `GET /cases`. A collection's `indicators` list is
  exactly the kind of field the brief's own example names ("Internal
  Blocklist", "Threat Hunt IOC Pack") suggest can grow to hundreds or
  thousands of entries — the same "heavy nested payload" reasoning that
  keeps `WorkspaceListItem` slim (it omits `investigation_summary`,
  `detection_package`, `correlation_summary`) applies here too.
  `CollectionListItem` carries every `Collection` field except `indicators`,
  replaced with `indicator_count: int`. The full list remains available from
  `GET /api/v1/collections/{id}`.
- **Indicator add/remove both operate on the same path**,
  `/api/v1/collections/{id}/indicator` (POST to add, DELETE to remove) —
  exactly as the brief's endpoint list specifies, with no
  `{indicator_id}` segment. This is a direct consequence of `Indicator`
  having no id of its own: `DELETE`'s request body carries `{type, value}`,
  matched server-side by the same normalized identity used for
  deduplication. The frontend's `removeIndicator()` sends this via a new
  `delWithPayload()` transport primitive (DELETE with a JSON request body
  *and* a JSON response body) — distinct from the existing `del()` (no
  body, no response) and `delWithBody()` (no request body, JSON response,
  used by Case Management's unlink) primitives, since this is the first
  endpoint in the codebase that needs a DELETE with both a request body and
  a response body.
- **Link endpoints return the updated `Collection`, not `204`** — same
  reasoning as Case Management's link/unlink: the collection still exists in
  a new state the caller almost always wants immediately.

## Frontend

Two new routes, mirroring the Cases list/detail split:

- **`/collections`** — browse (unfiltered `listCollections()`) or filter
  (`searchCollections()` with name/category/indicator-type/tag, switched to
  automatically once any filter field is non-empty) + a list of collection
  rows (source badge, category, indicator/investigation/case counts, tags)
  + an inline "+ New Collection" creation form (name, category, source).
- **`/collections/[id]`** — an "Edit" toggle revealing a form for
  name/description/category/tags (source shown read-only — it is set once
  at creation); an Indicators section listing every indicator (type badge,
  value, confidence, tags) with a "Remove" action per row and an inline
  add-indicator form (type `<select>` with all 18 options, value, tags,
  confidence); a Linked Investigations section (each row lazily fetches the
  referenced investigation's title/type via the existing, unmodified
  `getInvestigation()`) with a "paste an id, click Link" control — no unlink
  button, matching the API's link-only surface; a Linked Cases section, same
  shape, lazily fetching via the existing, unmodified `getCase()`.

No changes to any existing Workspace or Cases page. Two shared-transport
additions in `lib/api/client.ts`: `delWithPayload<T>()` (described above) —
`del()`, `delWithBody()`, `post()`, `put()`, `patch()` are all untouched.

## Compatibility

Verified, not merely assumed: Workspace's and Cases' own no-regression
suites (`tests/workspace/test_no_regression.py`,
`tests/cases/test_no_regression.py`) still pass unmodified, and a new
`tests/intel_collections/test_no_regression.py` proves every pre-Phase-9.1
route (every Workspace/Timeline/Graph/Export and every Case route) is still
registered with the same HTTP methods, every existing engine/framework
version constant is unchanged (including `CASE_FRAMEWORK_VERSION`), and the
CORS preflight for Cases' existing `PATCH` and Workspace's existing `PUT`
both still succeed alongside Collections' own new paths.

## Testing

197 new backend tests (`backend/tests/intel_collections/`): models (defaults,
validation bounds including `confidence`'s 0–100 range, `Indicator` has no
id field, not-frozen `model_copy` support), normalization (every type's
canonical form, the malformed-input-never-raises guarantee, IPv6
compressed/expanded/uppercase equivalence, URL path-case-sensitivity),
storage (mirroring `tests/cases/test_storage.py`'s exact scenarios), service
(creation, every list filter individually and combined, indicator
add/merge/remove including every individual merge rule — tag union,
first/last-seen widening, confidence/source/notes newest-wins, distinct
types with the same raw value never colliding — idempotent removal, linking
against real `WorkspaceService`/`CaseService` collaborators including
many-to-many and idempotency), API contract (every endpoint's success/error
shape, the route-ordering regression test, a full-lifecycle walk exercising
all ten endpoints in sequence), and the no-regression suite above. 30 new
frontend tests (`lib/api.test.ts`, extending the existing
single-file-per-`lib/api/`-directory convention). No test mocks
`WorkspaceService`/`CaseService` — every linking test uses real service/
storage pairs, matching this codebase's established preference for real
collaborators over mocks wherever they're this cheap to construct.

Browser-verified end-to-end against a live backend (34 checks, three
consecutive clean runs): create → browse → filter by name (empty and
non-empty results, exercising the `/search` endpoint) → open detail → edit
metadata → add an indicator → re-add the same indicator with a different
tag (confirms merge, not duplication, and that both tags survive) → seed a
real Workspace investigation and Case via the API → link both from the UI
→ attempt to link a nonexistent investigation (confirms the `404`/"Not
found." error banner) → remove the indicator → confirm the linked
investigation and case are both untouched → confirm the list page shows an
indicator *count*, never the raw array → filter by category (found and
not-found) → delete → confirm removal.

Two script-side false positives were found and fixed *in the verification
script*, not the application — both root-caused with direct diagnostics
before concluding "test bug, not app bug":

- A CSS `uppercase` class on the indicator-type badge renders "domain" as
  "DOMAIN" visually without changing the underlying DOM text node.
  Playwright's `page.inner_text()` maps to the browser's `HTMLElement.innerText`
  accessor, which (unlike `textContent`) reflects CSS `text-transform` — so an
  assertion checking for lowercase "domain" failed even though the correct
  data and markup were both present. Fixed by asserting the rendered
  ("DOMAIN") form.
- A `wait_for_function` intended to wait for a second, merging indicator-add
  to complete was written to check for the tag `"c2"` — but `"c2"` was
  already present in the DOM from the *first* add, before the second request
  even started, so the wait resolved instantly and the assertion ran against
  stale (pre-merge) state. Fixed by waiting for `"stage2"` (the tag unique
  to the second add) instead — a variant of the general "wait for something
  that can only be true after the state you care about" principle already
  documented from Case Management's own verification (waiting for a
  textarea to detach, or a counter heading's text, rather than content that
  could already be present).

## Known limitations

- **No enforcement that a collection's indicators share anything** — type,
  campaign, or otherwise. Collections organize by analyst judgment; nothing
  in the platform infers or validates a collection's internal coherence.
- **`metadata` has no defined schema or consumer.** It exists as an
  extension seam only, mirroring `Case.metadata`.
- **No audit trail of who added/removed/merged which indicator, when** —
  `updated_at` records that *something* changed, not what. Unlike Case
  Management's notes, Collections have no append-only history mechanism at
  all in this phase.
- **No unlink endpoint for Workspace/Case links** — see Relationships above;
  a deliberate adherence to the brief's exact endpoint list, not an
  oversight.
- **No case-level or collection-level export/report**, unlike Workspace's
  own `GET .../export`. Explicitly out of scope for this phase; see Future
  Extension Points.

## Future extension points

- **Symmetric unlink endpoints** (`DELETE .../workspace/{id}`,
  `DELETE .../case/{id}`), mirroring Case Management's own unlink pair —
  straightforward to add additively if a real need for it arises; the brief
  simply didn't ask for it this phase.
- **Automatic intelligence extraction from a Workspace investigation or
  Case** — explicitly deferred by the brief ("Extraction will come later").
  When it lands, it would populate `AddIndicatorRequest`-shaped data through
  the exact same `add_indicator()`/dedup-merge path this phase already
  built, not a new ingestion mechanism.
- **Detection Pack Generation, Threat Hunting, SOAR, and a Threat
  Intelligence Knowledge Base** — the four downstream capabilities the
  brief frames Collections as "the foundation for." None is started; each
  would consume `Collection.indicators` as input, the same way Detection
  Engineering (Phase 4.x) consumes an `Entity`.
- **Bulk indicator import/export** (CSV, STIX, MISP) — additive to
  `CollectionService`, not a redesign; the per-indicator dedup/merge logic
  already handles the identity question a bulk importer would need.
- Everything in the brief's Explicit Non-Goals (automatic IOC extraction,
  detection generation, Sigma, YARA, SOAR, TI provider integrations
  (VirusTotal, AbuseIPDB), AI, knowledge graph, analytics, dashboards,
  automation) remains unstarted, by design.
