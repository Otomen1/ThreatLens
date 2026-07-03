# Operational Dashboard v1

## Status

Complete. Frontend-and-backend addition, strictly downstream of the
Investigation Engine, the Reasoning Engine, the Detection Engine, the
Detection Knowledge Library, and the AI layer. None of those five subsystems
were modified — this doc records what was added around them, not a change to
any of them.

## Objective

Operational visibility only, for administrators/developers, never surfaced
inside the Investigation Workspace:

1. **System Health** — is each subsystem reachable/configured right now?
2. **API Consumption** — how much traffic, at what latency, with what
   success rate, has each subsystem handled this process's lifetime?
3. **Configuration Status** — what's configured/enabled, without ever
   showing a secret.

The dashboard is completely read-only. It cannot influence findings,
confidence, severity, recommendations, AI output, or generated/community
detections — there is no code path from `system/` back into `investigation/`,
`reasoning/`, `detection/`, `detection_library/`, or `ai/`.

## Isolation guarantee

`threatlens.system` imports *from* `providers`, `reference`, `ai`, `detection`,
`detection_library`, and (lazily) `api.health` — never the reverse. Nothing in
those five packages imports from or calls into `system`. The only place the
two sides meet is `api/app.py`, which:

- mounts the new `/api/v1/system/*` router alongside the existing routes, and
- adds a `time.perf_counter()` measurement plus one `record_*()` call
  immediately *after* each existing route already computed its (unchanged)
  response — never before, never altering what is computed or returned.

A `record_*()` call only *reads* fields off a response object the route
already produced (`ProviderSummary.status`, `AIExplanation.status`,
`DetectionPackage.artifacts`, …) and increments an in-memory counter. It
cannot raise in a way that fails the request (each call site is a plain
synchronous read + counter update, no I/O, no exceptions expected), and it
never touches the request or response bodies themselves.

## Architecture decisions

- **New package, not a bolt-on to `api/health.py`.** `api/health.py` (Phase
  3.17) answers "is this reachable, right now" for infra probes; the
  dashboard answers three broader questions (health *and* usage *and*
  config) for a human operator. `threatlens.system` **reuses**
  `api.health`'s existing `providers_health()`, `knowledge_health()`, and
  `ai_health()` functions directly (imported lazily, at call time, so the
  two modules never form an import-time cycle) rather than re-deriving
  "is this provider configured" logic a second time.
- **In-memory counters, not a database or a metrics stack.** The brief
  explicitly rules out Prometheus/Grafana. `system/metrics.py`'s
  `MetricsRegistry` is a single process-wide, lock-guarded dataclass of
  `CallCounter`/`RunningAverage` objects. It resets on restart by design —
  acceptable for a v1 whose job is "what has this running process seen,"
  not historical analytics.
- **Per-provider latency is the enclosing investigation's wall-clock time,
  not a true per-provider network timing.** TI and knowledge providers run
  concurrently inside one `asyncio.gather` in `InvestigationService.investigate()`
  (unmodified — see Isolation guarantee above). Measuring genuine per-provider
  latency would require instrumenting inside that gather, i.e. editing the
  Investigation Engine. Instead, `record_investigation()` times the whole
  `/investigate` call once and attributes that duration to every provider
  that participated. This is an honest, documented approximation (directionally
  useful — a slow provider skews investigations it's part of) rather than a
  precise per-provider figure.
- **Detection Knowledge's "last synchronized" / "cache size" are read
  directly from the sync cache file**, via the already-public
  `DetectionLibraryConfig.from_env()` + `read_cache()` (Phase 4.6), not
  stored redundantly on `system`'s side. When no cache directory is
  configured (the default — bundled-seed-only mode), both report `null`,
  which is the honest answer.
- **Rate-limit-remaining and provider-side cache hit/miss are always
  present in the schema but currently always `null`/`0`.** No provider in
  this codebase parses a rate-limit response header or implements caching
  yet; the fields exist so the dashboard doesn't need a contract change the
  day one does.

## Health design

`GET /api/v1/system/health` rolls seven checks into one
`Healthy | Degraded | Offline | Disabled` state each, plus an overall rollup
(worst of: any `Offline` → `Offline`; else any `Degraded` → `Degraded`; else
`Healthy`; a `Disabled` service never drags down the overall state — it's an
intentional configuration, not a fault):

| Service | Source | Never network? |
|---|---|---|
| Backend | trivially healthy (the process is answering) | yes |
| API | trivially healthy (the router is answering) | yes |
| Threat Intelligence Providers | `api.health.providers_health()` | yes (env-only) |
| Knowledge Providers | `api.health.knowledge_health()` | yes (offline datasets) |
| AI Provider | `api.health.ai_health()` | one lightweight `GET /api/tags` probe, only when AI is enabled — identical to the existing `/health/ai` guarantee |
| Detection Engine | `len(DetectionRegistry) > 0` | yes (in-process, no I/O) |
| Detection Knowledge Library | `DetectionKnowledgeService.stats().total_rules > 0`, wrapped in `try/except` so a corrupt cache degrades gracefully instead of raising | yes (reads the already-built in-memory index) |

## Metrics collection strategy

`system/record.py` is the only bridge between an API route's real response
and `system/metrics.py`'s counters:

- `record_investigation()` — per-provider success/failure (from
  `ProviderSummary.status`; `ok`/`not_found`/`partial` count as success,
  everything else as failure) and the investigation-level running averages
  (duration, finding count, recommendation count, confidence score).
- `record_ai_explanation()` — skipped entirely when `AIExplanation.status ==
  "disabled"` (nothing was attempted); otherwise records success/failure,
  latency, prompt size (`len(summary.model_dump_json())`, measured at the API
  boundary — never the provider's internal prompt template) and completion
  size (summed length of the returned explanation text fields).
- `record_detection_generation()` — one increment per generated
  `DetectionArtifact`'s language, plus the generation call's wall-clock time.
- `record_dkl_query()` — wraps both `/detection-knowledge/recommend` and
  `/detection-knowledge/search`.

All four are plain functions taking a `MetricsRegistry` and already-computed
model instances; they have no dependency on FastAPI, HTTP, or any request
context, so they're unit-tested directly (`tests/system/test_record.py`)
without a running server.

## Configuration strategy

`GET /api/v1/system/config` reshapes the same `providers_health()` /
`knowledge_health()` output used by the health endpoint into
`{name, display_name, configured, enabled}` — deliberately the narrowest
possible shape. No code path in `threatlens.system` reads an API key's
*value*, only whether the corresponding environment variable is present
(exactly what `api.health._provider_configured()` already did).

## Security considerations

- Every Pydantic response model in `system/schemas.py` carries only names,
  counts, timings, booleans, and short status strings — there is no field
  that could hold a secret, so there's no redaction logic to get wrong.
- `AIConfigStatus`/`AIUsage` expose the configured **model name** (e.g.
  `qwen3:4b`) but never the Ollama base URL (which could, in principle,
  embed a non-default host) and never a token.
- `_detection_knowledge_status()` and the DKL stats read wrap library
  access in `try/except Exception`, returning a friendly `Degraded` detail
  string — an internal exception message is never echoed into a response
  (verified in `test_health_endpoint.py::test_never_leaks_internal_errors`).
- All three endpoints are `GET`, side-effect-free, and require no request
  body — there is no mutation surface to abuse.

## Frontend

- `lib/api.ts` gained a "operational dashboard" section (types +
  `systemHealth()`/`systemUsage()`/`systemConfig()`), extending the existing
  typed client rather than a parallel one.
- `lib/dashboard.ts` — pure formatting helpers (status → badge color,
  latency/bytes/percent/timestamp formatting), unit-tested in
  `lib/dashboard.test.ts`.
- `components/dashboard/` — `StatusBadge`, `SystemHealthTab`,
  `ApiConsumptionTab`, `ConfigurationTab`, and `DashboardTabs` (a full-page
  ARIA-tabs component mirroring the roving-tabindex keyboard pattern already
  established by `investigation/shared/DetectionDisclosure.tsx`'s
  `DetailTabs` — not reused directly, since that component caps its panel at
  `max-h-32rem` with internal scroll, which fits a nested rule-detail card,
  not a full page). `ApiConsumptionTab` reuses the existing `Field`/`Badge`
  primitives from `DetectionDisclosure.tsx` directly.
- `app/dashboard/page.tsx` — a new top-level route, auto-refreshing every 60
  seconds (well above the "no faster than 30-60s" floor) plus a manual
  Refresh button, with independent loading/error states.
- The existing `SystemStatus` pill (top-right, unchanged internals) is now
  wrapped in a `next/link` to `/dashboard` — the only edit to that component.

## Testing summary

- **Backend** (`tests/system/`, 37 tests): pure unit tests for
  `CallCounter`/`RunningAverage`/`MetricsRegistry` and for each `record_*()`
  function against real (minimal) response model instances; integration
  tests per endpoint via `TestClient` covering all-services-present,
  AI-disabled, degraded-when-unconfigured, never-leaks-internal-errors,
  never-invokes-a-provider-lookup, counters-increment-after-a-real-investigate-call,
  and no-secret-values-in-any-response (including a literal env-var-value
  substring search). Full backend suite: 1617 passed, 1 skipped, unchanged
  outside `tests/system/`.
- **Frontend**: 20 new unit tests for `lib/dashboard.ts`'s formatters; a
  Playwright smoke pass (throwaway, not committed) covering the status-pill
  link, both tabs' content, keyboard tab navigation with focus verification,
  the Configuration tab's no-secret check, the Refresh button, responsive
  layout at 390px, and a full re-run of the existing Investigation Workspace
  flow to confirm zero regression.

## Performance summary

- Health checks: no new network calls beyond the pre-existing `/health/ai`
  probe; everything else is an in-memory read or an env-var check.
  `/api/v1/system/health` responds in low single-digit milliseconds locally.
- Usage/config: `MetricsRegistry` reads are `O(providers)` dict iterations;
  no historical scan, no disk I/O beyond one optional cache-file `stat()`
  call for Detection Knowledge's cache size.
- Instrumentation overhead on the real routes: one `time.perf_counter()`
  pair and one counter-dict update per request — no measurable added latency.
- Frontend auto-refresh is capped at 60s; a manual Refresh re-fetches all
  three endpoints in parallel (`Promise.all`).

## Explicit non-goals (respected)

- No Prometheus/Grafana/monitoring platform integration.
- No polling faster than 30-60s.
- No authentication redesign.
- No historical-investigation scanning.
- No change to `InvestigationSummary`, the Reasoning Engine, the Detection
  Engine, the Detection Knowledge Library's rule content/matching/licensing,
  or the AI layer's prompts/output contract.
- No Phase 5 (Exposure Intelligence) work.
