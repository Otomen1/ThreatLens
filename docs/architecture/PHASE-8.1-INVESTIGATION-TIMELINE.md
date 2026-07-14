# Phase 8.1 — Investigation Timeline Framework

## Status

Complete. A pure, deterministic, **read-only** consumer of a saved
investigation's existing outputs. **Not a new intelligence engine** — it
derives chronological events only from evidence that already carries an
explicit, timezone-aware timestamp. It never invents a timestamp, estimates
chronology, or infers causality. No AI, no probabilistic inference.

## Purpose

A saved `WorkspaceInvestigation` (Phase 8.0) bundles an `InvestigationSummary`
and, optionally, a `DetectionPackage`/`CorrelationSummary` — but nothing
about *when* the underlying observations happened. Phase 8.1 answers that
question the only way this codebase's evidence model allows: by reading the
one timestamp field that already exists on evidence
(`Evidence.observed_at`) and presenting whatever is genuinely there, in
order — nothing more, nothing invented.

## Architecture

`backend/src/threatlens/timeline/`:

| Module | Role |
|---|---|
| `models.py` | `TimelineEvent`, `Timeline`, `TimelineSourceType` — frozen value objects. |
| `engine.py` | `is_valid_evidence_timestamp`, `compute_event_id`, `collect_events`, `sort_events` — the pure derivation logic. No I/O, no wall clock. |
| `service.py` | `TimelineService` — adapts a `WorkspaceInvestigation` into a `Timeline`. |

Data flow: `GET /api/v1/workspace/{id}/timeline` → `WorkspaceService.get(id)`
(existing, unchanged — 404 if missing) → `TimelineService.build(record)` →
`engine.collect_events(record.investigation_summary)` → `engine.sort_events(...)`
→ `Timeline`. Nothing is written back to the saved record; nothing is
cached; every call recomputes from the same source, deterministically.

## Event model

```python
class TimelineEvent(BaseModel):        # frozen
    event_id: str                       # content-addressed
    timestamp: datetime                 # from Evidence.observed_at — never invented
    event_type: EvidenceType             # reused, not duplicated
    title: str                          # = Evidence.summary, verbatim
    description: str                    # = Evidence.value or "", verbatim
    source_type: TimelineSourceType       # which engine output this came from
    source_id: str                      # the (smallest) citing Finding.id
    severity: Severity | None            # copied from the citing finding(s); worst-case if >1
    evidence_references: tuple[str, ...]  # every Finding.id that cited this evidence

class Timeline(BaseModel):             # frozen
    investigation_id: UUID
    entity_type: EntityType
    entity_value: str
    generated_at: datetime              # inherited, never datetime.now()
    events: tuple[TimelineEvent, ...]
```

`event_type` reuses `threatlens.providers.results.EvidenceType` (13 values:
`classification`, `detection`, `abuse_confidence`, `malware_family`,
`pulse_match`, `sandbox_observation`, `blocklist`, `category`,
`communication`, `first_seen`, `last_seen`, `tag`, `other`) — the existing
closed vocabulary describing what kind of observation a piece of evidence
already is. `severity` reuses `threatlens.reasoning.models.Severity`.
Neither is redeclared.

`title`/`description` are populated from `Evidence.summary`/`Evidence.value`
**verbatim** — never composed into new prose. A finding's own title, or any
other narrative, is deliberately not blended in: the timeline shows what the
evidence itself said, not a rephrasing of it.

## Supported evidence sources

Only one, in this phase: `InvestigationSummary.findings[].evidence[]` →
`WeightedEvidence.evidence` (an `AttributedEvidence`) → `.evidence` (the raw
`providers.results.Evidence`) → `.observed_at`.

**Detection and Correlation outputs are explicitly out of scope for this
phase — not because they were overlooked, but because neither carries a
usable event timestamp:**

- `DetectionPackage`/`DetectionArtifact` have no per-artifact timestamp at
  all — only `DetectionMetadata.generated_at`, inherited from the source
  `InvestigationSummary` and describing when the *package was generated*,
  never when a security event was *observed*.
- `CorrelationSummary`/`CorrelationObservation` are the same shape:
  `CorrelationObservation` carries no timestamp of its own; only
  `CorrelationMetadata.generated_at` exists, with the identical
  processing-time-not-event-time meaning.

Treating either `generated_at` as an event time would be exactly the
invented chronology this framework refuses to produce — and would also
misrepresent a *duplicate* of the investigation's own `generated_at` as if
it were new, independent information. `TimelineSourceType` is defined as a
closed enum with room to grow (`DETECTION_ARTIFACT`/`CORRELATION_OBSERVATION`
are documented, not added) for if a future phase gives either engine a real
per-item timestamp.

## Timestamp policy (the critical design rule, made concrete)

`is_valid_evidence_timestamp(value: datetime | None) -> bool` is the single
gate every piece of evidence passes through:

```python
return value is not None and value.tzinfo is not None
```

Two things make a timestamp unusable:

1. **Absent** (`None`) — the provider never reported one. Never
   backfilled with `datetime.now()`.
2. **Timezone-naive** — present, but ambiguous. A naive `datetime` cannot be
   deterministically compared against the timezone-aware datetimes the rest
   of the codebase uses (`reason(..., now=...)`'s own convention) without
   *assuming* a timezone it doesn't actually carry. Assuming one would
   itself be invented information, so a naive timestamp is treated as
   missing rather than silently coerced to UTC. This also sidesteps a real
   Python footgun: sorting a mix of naive and aware datetimes raises
   `TypeError` — by construction, only aware datetimes ever reach
   `sort_events`.

If evidence fails this check, it contributes no timeline event — silently,
not as an error. An investigation whose providers reported no timestamps at
all yields a well-formed, empty `Timeline`, which is a valid, non-error
result (see `Timeline.is_empty`).

## Event identity (content-addressed, per the brief)

```python
def compute_event_id(*, event_type, subject_type, subject_value, timestamp, summary, value) -> str:
    payload = "|".join([event_type, subject_type, subject_value.strip().lower(),
                         timestamp.isoformat(), summary.strip(), (value or "").strip()])
    return f"evt_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"
```

Mirrors `correlation.engine.compute_observation_id`'s exact shape (`sha256`,
16 hex chars, a short prefix). Hashes only stable evidence content — never
the current time, a generation timestamp, a random UUID, or list position —
so the same underlying evidence always produces the same `event_id`,
regardless of which finding, or how many findings, cite it, or what order
they're processed in.

## Deduplication

Two evidence citations that hash to the same `event_id` are, by
construction, the same underlying observation. `collect_events` groups by
`event_id` before building the final `TimelineEvent` list, so **the same
evidence cited by two or more findings collapses into exactly one canonical
event** — never two, never as many as the number of citing findings.

That one canonical event still carries full provenance:

- `evidence_references` — the sorted, deduplicated set of every finding id
  that cited it (so nothing about a multi-citation is lost).
- `source_id` — the lexicographically smallest of those ids, for a single,
  stable "primary" pointer.
- `severity` — the **worst** (highest) severity among every citing finding,
  never the first-seen or an average; a genuinely ambiguous multi-citation
  never gets silently understated.

Two evidence items are only merged when their *entire* content matches
(type, subject, timestamp, summary, value) — different `value`s on
otherwise-identical evidence, or the same evidence content on two different
subjects, are deliberately **not** merged (verified explicitly in
`test_engine.py::TestDeduplication`).

## Ordering

`sort_events` orders by `(timestamp, event_type.value, event_id)` — every
field a plain, total-order-comparable value, so the sort is fully
deterministic regardless of input order:

1. **Timestamp**, ascending — the actual chronology.
2. **Event type** — breaks ties between events at the identical instant.
3. **Event id** — the final, always-unique tiebreaker (two events can share
   a timestamp and an event type but never an identical hash unless they're
   the same evidence, which is already deduplicated).

Never insertion order, never list position. `test_reordering_input_evidence_does_not_change_output_order`
proves this directly: shuffling the input evidence list produces a
byte-identical sorted output.

## API

`GET /api/v1/workspace/{investigation_id}/timeline` — added to the existing
`api/routes/workspace.py` router (a sub-resource of a saved investigation,
not a new top-level subsystem). Loads the record via the unmodified
`WorkspaceService.get()` (404 via the existing `InvestigationNotFoundError`
→ `HTTPException`), then hands it to `TimelineService.build()`. **Every
existing workspace endpoint — `POST`/`GET`/`GET {id}`/`PUT {id}`/`DELETE
{id}` — is unchanged**; this is a pure addition.

## Frontend

- **`frontend/lib/api/workspace.ts`** gained `Timeline`/`TimelineEvent`
  types and `getInvestigationTimeline(id, signal)`. `event_type`/`source_type`
  are left as plain `string` (mirroring `Evidence.type` in `./investigation`,
  which does the same) rather than exact unions — nothing in the UI branches
  on a specific value.
- **`frontend/app/workspace/[id]/page.tsx`** gained one new section,
  `TimelineSection` — collapsed by default, fetched lazily on first expand,
  mirroring the existing `DetectionEngineeringCard`'s disclosure pattern
  exactly (same loading/failed/empty/data states, same shared `Chevron`
  component). Each event row shows its timestamp, title, event type,
  severity (when present), and description — plain list, no graph, no
  animation library, no interactive timeline widget, per the brief. The
  section never re-sorts or re-derives what the backend returns.

## Testing

`backend/tests/timeline/` (81 tests):

- **`test_models.py`** — the event/timeline envelope: frozen, defaults,
  validation, JSON round-tripping.
- **`test_engine.py`** — the timestamp policy (valid/missing/naive/mixed),
  content fields (`event_type` reuse, `title`/`description` verbatim,
  `severity` copied), deduplication (collapse, multi-reference, worst-case
  severity, smallest-id `source_id`, non-merge of genuinely distinct
  evidence), multiple evidence sources, `compute_event_id` determinism and
  sensitivity to every input field, `sort_events` ordering including equal
  timestamps and input-order independence, and read-only behavior (the
  source `InvestigationSummary` is provably unchanged after derivation).
- **`test_service.py`** — the `WorkspaceInvestigation` adaptation, including
  the no-attached-summary fallback (`entity_type` from the record,
  `generated_at` from the record's `updated_at`) versus the normal path
  (both from the summary).
- **`test_api.py`** — the full HTTP contract: `200`/`404`/`422`, response
  shape, the no-summary empty-timeline case, a real `/investigate` summary
  round-tripped through save → timeline, repeated-fetch byte-identity, and
  that the saved record is never mutated by fetching its timeline.
- **`test_no_regression.py`** — every pre-Phase-8.1 route (via the OpenAPI
  schema), every existing workspace operation's HTTP methods, and every
  engine version constant, all unchanged; the new timeline route is purely
  additive.
- **`test_golden.py`** + **`corpus.py`** (10 scenarios, `golden.json`) — a
  small, focused golden regression (`THREATLENS_UPDATE_GOLDEN=1` to
  regenerate, matching Correlation's exact mechanism) covering every
  documented policy decision: empty investigation, no evidence, a single
  timestamped event, missing/naive timestamps (alone and mixed with valid
  ones), duplicate evidence across findings, multiple distinct findings,
  equal-timestamp tie-breaking, and one finding with multiple evidence
  items. Deliberately smaller than Correlation's 76-scenario corpus: the
  Timeline Engine's behavior space is a short, enumerable set of policy
  decisions rather than a combinatorial rule library, so this corpus gives
  the same regression-locking value at a fraction of the size.

Frontend: 5 new tests in `frontend/lib/api.test.ts` (this codebase's
established single file for the whole `lib/api/` barrel — there are no
component-rendering tests anywhere in this project, since `vitest.config.ts`
runs `environment: "node"`, not jsdom). The new UI was verified with a real,
scripted Playwright browser session against a live backend: a hand-built
investigation with three evidence items — one duplicated across two
findings, one with no timestamp — correctly produced a 3-event, chronologically
ordered timeline with the duplicate collapsed and its severity taken as the
worse of the two citing findings; a bare investigation with no attached
summary correctly showed the "no timestamped evidence" empty state.

Full suite after this phase: **2,577 backend tests passed, 1 skipped** (was
2,496). Ruff and mypy (`--strict`) clean across 182 source files (was 178).
Frontend: 127 Vitest tests passed (was 122); production build clean,
including the timeline section on the existing `/workspace/[id]` route (no
new route — the endpoint is a sub-resource, not a page).

## Known limitations

- **Detection and Correlation contribute no events** in this phase — see
  "Supported evidence sources" above. This is a direct consequence of
  neither engine's output carrying a real per-item timestamp today, not an
  oversight; extending either would require that engine to gain one first.
- **A timezone-naive `observed_at` is treated as absent**, not coerced to
  UTC or any other zone. If a provider or a future test fixture supplies a
  naive datetime, it silently produces no event — by design (see "Timestamp
  policy"), but worth stating plainly since it's easy to trip over
  accidentally when writing new evidence-producing code.
- **No causality or relationship is ever asserted between events.** Two
  events sorted adjacently in time are not claimed to be related, still
  less that one caused the other — the timeline is order, not narrative.
- **No cross-investigation timeline.** Each `Timeline` is scoped to exactly
  one saved investigation; there is no merged view across multiple saved
  cases in this phase.
- **No persistence of timeline data.** Per the brief's preference,
  `WorkspaceInvestigation` gains no new field — a `Timeline` is always
  recomputed from the saved record's existing `investigation_summary`, never
  stored. This trades a (currently negligible) recomputation cost for zero
  risk of a stored timeline silently drifting from its source.
- **No pagination.** Acceptable at the intended scale (single saved
  investigation's own evidence); revisit if a future phase's evidence volume
  grows enough to matter.

## Future extensions (explicitly out of scope for this phase)

Per the brief: Evidence Graph, Analyst Notes, Audit History,
Export/Reporting, Authentication, RBAC, database migration, STIX/TAXII,
SOAR, and any other future phase are not started. Natural next steps this
phase's design already accommodates without rework: extending
`TimelineSourceType` if Detection or Correlation gain real per-item
timestamps; a cross-investigation merged timeline; export formats reusing
the existing `Timeline`/`TimelineEvent` shape verbatim.

## Readiness review

**GO.**

- No engine changes: Reasoning, Detection, Correlation, Exposure, and
  Identity are byte-for-byte unmodified (engine version constants
  unchanged; verified by `test_no_regression.py`).
- No existing API changes: every pre-Phase-8.1 workspace operation
  (`POST`/`GET`/`GET {id}`/`PUT {id}`/`DELETE {id}`) keeps its exact HTTP
  methods and response shape; the new timeline route is purely additive.
- No AI, no invented timestamps, no inferred chronology without timestamp
  evidence, no inferred causality — enforced by `is_valid_evidence_timestamp`
  and tested explicitly.
- Stable ids (`compute_event_id`, content-addressed) and stable ordering
  (`sort_events`, three-key deterministic tiebreak), both proven by repeated
  runs, input-order shuffling, and the golden corpus.
- Existing tests: full backend suite green, **2,577 passed / 1 skipped** (up
  from 2,496 — the delta is entirely new timeline + regression tests).
  Frontend: 127 Vitest tests passed (up from 122), production build clean.
- Manually verified end-to-end in a real browser against a live backend with
  hand-built, realistic evidence: correct chronological order, correct
  deduplication, correct worst-case severity, and the correct empty state
  for an investigation with no attached summary.
