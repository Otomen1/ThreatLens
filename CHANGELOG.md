# Changelog

All notable changes to ThreatLens are documented here. The project follows
[Semantic Versioning](https://semver.org/) and (from v1.0.0 on) the
[Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

### Added — Phase 8.1: Investigation Timeline Framework

- **New `backend/src/threatlens/timeline/` package** — a pure, deterministic,
  **read-only** consumer of a saved investigation's existing evidence, not a
  new intelligence engine. Derives chronological `TimelineEvent`s only from
  evidence that already carries an explicit, timezone-aware timestamp
  (`Finding.evidence[].evidence.evidence.observed_at`); never invents one,
  never estimates chronology, never infers causality. Evidence with no valid
  timestamp is silently omitted, never backfilled with the current time.
- **Detection and Correlation deliberately contribute no events**: neither
  `DetectionPackage`/`DetectionArtifact` nor
  `CorrelationSummary`/`CorrelationObservation` carries a per-item event
  timestamp — only a package/summary-level `generated_at` inherited from the
  investigation, describing when that output was *computed*, never when a
  security event was *observed*. Treating it as one would be exactly the
  invented chronology this framework refuses to produce.
- **Content-addressed `event_id`** (`sha256`, mirrors
  `correlation.engine.compute_observation_id`'s exact shape): hashes only
  stable evidence content, never a timestamp, random UUID, or list position.
  The same underlying evidence always produces the same id — which is also
  the mechanism that collapses duplicate evidence (the same observation
  cited by more than one finding) into **one canonical event**, retaining
  full provenance (`evidence_references`: every citing finding id;
  `severity`: the worst across all of them).
- **Deterministic ordering**: `(timestamp, event_type, event_id)` — proven
  independent of input order and stable across repeated runs.
- **API**: `GET /api/v1/workspace/{id}/timeline`, added to the existing
  workspace router as a sub-resource. Every existing workspace endpoint
  (`POST`/`GET`/`GET {id}`/`PUT {id}`/`DELETE {id}`) is unchanged.
- **Frontend**: `getInvestigationTimeline()` in `lib/api/workspace.ts`; a
  new, collapsed-by-default "Timeline" section on the workspace detail page
  (`/workspace/{id}`), fetched lazily on first expand — mirrors the existing
  Detection Engineering card's disclosure pattern exactly. Plain
  chronological list; no graph, no animation library, no interactive
  timeline widget.
- **Testing**: 81 new backend tests (`backend/tests/timeline/`) — models,
  engine (timestamp policy, deduplication, identity, ordering, read-only
  behavior), service, API contract, a dedicated no-regression suite, and a
  10-scenario golden corpus (`THREATLENS_UPDATE_GOLDEN=1` to regenerate,
  matching Correlation's exact convention). 5 new frontend tests
  (`lib/api.test.ts`); the new UI verified with a real, scripted browser
  session against a live backend using hand-built evidence including a
  duplicate citation and a missing timestamp. Backend suite: **2,577
  passed, 1 skipped** (was 2,496). Ruff/mypy (strict) clean across 182
  source files (was 178). Frontend: 127 Vitest tests passed (was 122).
- **Docs:** `docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md`.

### Added — Phase 8.0: Investigation Workspace Framework

- **New `backend/src/threatlens/workspace/` package** — a workflow and
  persistence layer over the completed analytical pipeline, **not a new
  intelligence engine**. Save, load, update, delete, list, filter, and
  search completed investigations. No AI, no reasoning, no correlation, no
  authentication (single-user, self-hosted), no database in this phase.
- **`WorkspaceInvestigation`** (`models.py`): the saved record. Its metadata
  envelope (`id`, `title`, `status`, `tags`, `summary`, `severity`,
  `investigation_type`, timestamps) is new; `investigation_summary`,
  `detection_package`, and `correlation_summary` are the **existing**
  Reasoning/Detection/Correlation engines' own output models, imported and
  persisted verbatim — none is redeclared. Unlike every other model in the
  codebase it is **not frozen**: it is the one model designed to be mutated
  over its lifetime, always via a fresh `model_copy`, never in place. `id`
  is a random `uuid4()` (matching `search_id`/`investigation_id`), not
  content-addressed like `CorrelationObservation`/`DetectionPackage` — two
  saves of identical content are two distinct records, not a collision.
- **Storage abstraction** (`storage.py`): `WorkspaceStorage` (ABC) +
  `LocalFileStorage` — one JSON file per investigation, atomic writes
  (temp file + rename), corrupt-file-resilient listing. The interface is
  the seam for a future database-backed implementation; none is built here.
- **`WorkspaceService`** (`service.py`): save/get/update/delete/list, with
  update using PATCH-style merge semantics (`exclude_unset`) and list
  supporting `status`/`severity`/`investigation_type`/`tag`/free-text
  `query` filters, AND-combined, sorted most-recently-updated first.
- **REST API** (`api/routes/workspace.py`, mounted at `/api/v1/workspace`):
  `POST` (save, `201`), `GET` (list, metadata-only projection), `GET /{id}`
  (full record, `404` if missing), `PUT /{id}` (partial update, `404` if
  missing), `DELETE /{id}` (`204`, `404` if missing).
- **One CORS fix required by the new endpoints:** `api/app.py`'s
  `CORSMiddleware` allowed only `GET, POST` — every prior route was one or
  the other, so the gap was never exercised. The new `PUT`/`DELETE`
  endpoints failed their cross-origin preflight in the documented
  separately-hosted-frontend configuration (found via manual browser
  verification, not by the same-origin API tests, which can't see a
  preflight at all). Fixed by adding `PUT, DELETE` to `allow_methods` —
  additive, verified to leave every existing route's CORS behavior
  unchanged.
- **Frontend:** `frontend/lib/api/workspace.ts` (typed client, reusing
  `InvestigationSummary`/`EntityType`/`DetectionPackage` rather than
  redeclaring them); `client.ts` gained `put()`/`del()` (previously only
  `post()`/`get()` existed, since no endpoint had needed them). A new
  `/workspace` list page (search + status/severity filters + delete) and
  `/workspace/{id}` detail page (status editing; reuses the existing, pure
  `InvestigationSummaryCard`/`RecommendationRollup`/`FindingsSection`
  components verbatim). A new `SaveInvestigationButton`, added to the
  existing `components/InvestigationWorkspace.tsx` display component, is
  the only change to that file (one import, one JSX block).
- **A disclosed naming collision:** "Investigation Workspace" already names
  the existing per-search analyst display UI
  (`components/InvestigationWorkspace.tsx`, versioned "v2" as of v1.1.1).
  This phase's new persistence layer keeps the brief's name for the
  *feature* but lives entirely under its own `workspace` namespace in code
  on both sides (backend package, frontend routes/components) to avoid any
  code-level collision; see the architecture doc for the full
  disambiguation.
- **Testing:** 95 new backend tests (`backend/tests/workspace/`) — models,
  storage, service, API contract, and a dedicated `test_no_regression.py`
  proving every pre-Phase-8.0 route, engine version constant, and (via a
  real cross-origin `OPTIONS` preflight, not a same-origin call) CORS
  behavior is unchanged. 18 new frontend tests
  (`frontend/lib/api.test.ts`, the established single file covering the
  whole `lib/api/` barrel — this codebase has no component-rendering tests
  anywhere, so the new UI was instead verified with a real, scripted
  Playwright browser session against a live backend: search → save → list
  → filter → detail → status update → delete, which is also how the CORS
  bug above was found). Backend suite: **2,496 passed, 1 skipped** (was
  2,493). Ruff/mypy (strict) clean across 178 source files (was 175).
  Frontend: 122 Vitest tests passed (was 104); production build clean with
  both new routes registered.
- **Docs:** `docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md`.

### Added — Phase 7.1: Correlation Rule Library Expansion

- **Rule library expanded from 12 to 70 rules**
  (`backend/src/threatlens/correlation/rules/`), organized into 7 domain
  modules (`seed` — the unchanged Phase 7.0 set, `compound`,
  `infrastructure`, `vulnerability`, `malware`, `threat_actor`, `campaign`,
  `mitre`) replacing the single Phase 7.0 `rules.py` file. Every rule is
  still declarative `CorrelationRule` data interpreted by the engine's one
  generic evaluator — **zero changes to the engine, registry, service,
  summary generation, output schemas, or the public API.**
- **Coverage, not padding:** every malware/actor/campaign/technique pairing
  that previously existed only cross-subject gets a same-subject variant (a
  materially tighter binding), the previously-unused disposition categories
  (`CONTESTED`, `ACTION_REQUIRED`, `INFORMATIONAL`) are combined with the
  domain categories that benefit most, and 6 new three-signal *compound*
  rules capture escalations (e.g. malicious + exposed + known-exploited)
  that are strictly more specific than any one of their two-category subset
  rules — additive, not competing: both the compound rule and its subset
  rules can fire on the same investigation.
- **Deliberately does not build tactic-specific rule modules**
  (persistence/execution/discovery/collection/exfiltration/
  command-and-control/lateral-movement/privilege-escalation/impact): the
  Reasoning Engine's `FindingCategory` vocabulary carries one
  tactic-agnostic `ATTACK_PATTERN` value, so per-tactic rules would differ
  only in display text, not in what they match — exactly the semantic
  duplication this expansion avoids. All technique-co-occurrence rules live
  in one `mitre.py`; see the architecture doc's "Known Limitations."
- **One disclosed, additive model touch:** 26 new `CorrelationCategory`
  enum values (`models.py`) — the same purely-additive pattern as Phase
  5.3's `ExposureCapability.INTERNET_NOISE`. Related rules share a category
  when they represent the same *kind* of pattern (e.g. every "+contested"
  rule across every domain emits `FINDING_CONTESTED`) rather than each
  rule getting a bespoke value, so 38 categories back 70 rules.
- **Verified non-duplication programmatically:** a new registry test
  asserts no two of the 70 rules share an identical
  `(required_categories, same_subject)` signature — the real invariant that
  replaces Phase 7.0's incidental 1:1 rule-to-category test.
- **New rule-count performance benchmark** (`perf.py::measure_rule_scaling`,
  synthetic benchmark-only rules, never registered in the real registry):
  25/50/100 registered rules scale linearly (1.73× per-rule spread) at a
  fixed investigation size — independent of Phase 7.0's existing
  observation-count benchmark (unchanged, still 1.09× linear).
- **Testing:** golden corpus grew from 18 to 76 scenarios (one per new rule,
  generated programmatically rather than hand-written, plus the 18
  unchanged Phase 7.0 scenarios); `test_rules.py`'s parametrized fire/no-fire
  tests automatically extended from 12 to 70 rules with no test-file change.
  Backend suite: **2,399 passed, 1 skipped** (was 2,281). Ruff/mypy (strict)
  clean across 171 source files (was 163). No frontend changes.
- **Docs:** `docs/architecture/PHASE-7.1-CORRELATION-RULE-LIBRARY.md`.

### Changed — Phase 7.0.1: API composition-layer cleanup (no behavior change)

- **`backend/src/threatlens/api/app.py`** is now a pure composition root.
  Every subsystem's endpoints moved into their own router under the new
  `api/routes/` package (`investigation.py` — `/detect` + `/investigate`;
  `ai.py` — `/explain`; `detection.py` — `/detections`;
  `detection_knowledge.py` — both `/detection-knowledge/*` routes;
  `exposure.py`, `identity.py`, `correlation.py` — their framework-status
  endpoints), mirroring the existing `system/router.py` pattern. `app.py`
  now only builds the FastAPI app, configures CORS, and includes routers.
  All endpoint URLs, request/response models, dependency-injection
  overrides (`get_investigation_service`, `get_ai_service`,
  `get_knowledge_service` — still importable from `threatlens.api.app`),
  metrics recording, middleware, and OpenAPI output are unchanged.
- **`backend/src/threatlens/api/timing.py`** (new) — a one-function
  `elapsed_ms(start)` helper replacing the `_duration_ms = (time.perf_counter()
  - _start) * 1000` line duplicated across five endpoints.
- **`frontend/lib/api.ts`** (973 lines) split into `frontend/lib/api/`
  (`client.ts`, `investigation.ts`, `ai.ts`, `detection.ts`,
  `detectionKnowledge.ts`, `exposure.ts`, `identity.ts`, `correlation.ts`,
  `system.ts`, plus an `index.ts` barrel). Every existing `from "@/lib/api"`
  / `from "./api"` import continues to resolve unchanged; no exported name,
  type, or function signature changed.
- Two exposure test files (`tests/exposure/test_api.py`,
  `tests/exposure_validation/test_exposure_freeze.py`) updated to
  monkeypatch the exposure registry/service singleton in its new home
  (`api.routes.exposure`) instead of `api.app` — the only test changes this
  cleanup required.
- Refreshed the `api/app.py` and `api/__init__.py` module docstrings, which
  still described a single-endpoint Phase 1.1.5 API.
- No new functionality, no API contract changes, no engine changes. Follows
  from the Phase 6.0/7.0 Merge Readiness Review's High-severity findings on
  `api/app.py` and `lib/api.ts` growth. Backend suite: **2,281 tests**
  (2,280 passed, 1 skipped), unchanged. Frontend: **104 tests**, unchanged.
  Ruff/mypy (strict) clean across 163 backend source files (was 154).

## [1.2.0] — 2026-07-06

### Added — Phase 7.0: Investigation Correlation Engine Framework (framework + seed rules)

- **New engine** (`threatlens.correlation`) — a pure, deterministic consumer of
  a completed `InvestigationSummary` that combines its **existing** findings
  into higher-level correlation *observations* (e.g. "malicious infrastructure
  with exposed services", "known malware associated with an observed ATT&CK
  technique"). It never invents evidence, never scores, and never produces
  confidence/severity/priority — those remain the Reasoning Engine's job. Every
  observation references the source findings it combines, so every correlation
  is fully explainable. No AI, no ML, no probabilistic inference.
- **Declarative rules + one generic evaluator.** A `CorrelationRule` is frozen
  data (required finding categories, a same-subject/cross-subject flag, a
  relationship, a category, a title, a priority); a single evaluator interprets
  every rule, so there is no per-rule code. Ships a **12-rule seed set** so the
  pipeline is exercised end-to-end — rule expansion is Phase 7.1.
- **Content-addressed, timestamp-independent identity.** Observation and
  summary ids hash only stable values (rule, category, subject, source finding
  ids / entity, source engine version, observation ids) — never `generated_at`
  — so re-running correlation on the same investigation yields identical ids.
  Read-only: the input `InvestigationSummary` is never mutated. Deterministic
  ordering throughout (rules by priority-then-id, observations by
  category-subject-id, matches by rule id).
- **Mirrors the Detection Engine.** Same shape as `detection/` (pure
  `InvestigationSummary` consumer, content-addressed package, registry as the
  extension seam) — `CorrelationRegistry`, `CorrelationService`,
  `correlate(summary) -> CorrelationSummary`. Depends only on the frozen
  `reasoning`/`entities` contracts; nothing else imports from it.
- **`GET /api/v1/correlation`** — a pure readiness probe (`status`, `message`,
  `framework_version`, `rules_registered`), never running a correlation and
  never touching the network. A new placeholder page at **`/correlation`**
  shows Engine Ready, registered-rule count, and architecture version. Framework
  version starts at `0.1.0`; it moves to `1.0` after the rule set is expanded
  and validated (the Reasoning/Detection/Exposure convention). Not integrated
  into `/investigate`.
- **No changes to any existing subsystem**: Threat/Knowledge Intelligence, the
  Investigation Engine, the frozen Reasoning/Detection/Exposure Engines, the
  Detection Knowledge Library, the Operational Dashboard, the AI layer, or the
  Identity framework.
- **Testing:** 79 new offline tests (`backend/tests/correlation/`) — models,
  each of the 12 seed rules, registry ordering, engine determinism/identity/
  read-only/edge cases, aggregation, the service, the API endpoint, an
  18-scenario CI-gated golden snapshot, and a perf smoke. Correlation scales
  **linearly** (per-observation cost varies 1.09× from 10 to 500 observations;
  no optimization performed). Backend suite: **2,280 passed, 1 skipped** (was
  2,201). Frontend: **104 tests** (was 101; +3 for the correlation client);
  build clean with the new `/correlation` route. Ruff/mypy (strict) clean across
  154 source files. The golden-regression CI job now also runs
  `tests/correlation`.
- **Docs:** `docs/architecture/PHASE-7.0-CORRELATION-FRAMEWORK.md`.

Rule expansion (Phase 7.1), the Timeline Engine, the Graph Engine, Case
Management, SOAR, playbooks, and a MITRE attack graph all remain explicitly
deferred to later, unstarted phases.

### Added — Phase 6.0: Identity Intelligence Framework (architecture only)

- **New framework** (`threatlens.identity`) — a fourth intelligence subsystem,
  opened exactly as Exposure Intelligence's Phase 5.0 was. Threat Intelligence
  answers "is this IOC malicious?", Exposure Intelligence "where is this entity
  exposed?"; Identity Intelligence answers **"what is known about this
  identity?"** (breaches, credential exposure, paste history, linked accounts,
  directory profile, group membership, role assignments, MFA state, sign-in
  activity, first-party risk signals). Purely descriptive — no score, no
  compromised/safe verdict; a provider's own risk signal is quoted as a
  third-party fact, never a ThreatLens verdict. A separate framework at every
  layer: no shared models, no shared registry, no import in either direction
  with any other subsystem (only the shared `entities/` contract).
- **Zero concrete providers.** Every code path (registration, routing,
  aggregation, the service) is real and tested against an empty registry —
  `IdentityService.investigate()` returns a well-formed, empty
  `IdentitySummary` through the same aggregation path a future provider will
  use unmodified. Mirrors the proven `exposure/` shape: closed-vocabulary
  enums (`IdentityCapability`, `IdentityStatus`, …), frozen Pydantic models
  (`IdentityFinding`, `IdentityAsset`, `IdentityEvidence`, `IdentitySummary`,
  …), an `IdentityProvider` ABC, a registry that registers and routes, a pure
  `merge_findings` aggregation, and `IdentityService`. Cache
  (`IdentityCache` + an in-memory default) and config
  (`IdentityConfig.from_env()` — `IDENTITY_ENABLED`, `IDENTITY_CACHE_ENABLED`,
  `IDENTITY_CACHE_TTL`, `IDENTITY_TIMEOUT`, `IDENTITY_RATE_LIMIT_PER_MINUTE`)
  are interfaces/settings only — no Redis, no persistence, no secrets, nothing
  wired in yet.
- **`GET /api/v1/identity`** — a pure readiness probe (`status`, `message`,
  `framework_version`, `providers_registered`), not integrated into
  `/investigate` and never touching the network. A new placeholder page at
  **`/identity`** shows Framework Ready, provider count, and architecture
  version. Framework version starts at `0.1.0`; it moves to `1.0` only after
  Phase 6.1+ providers ship and the subsystem is validated end-to-end (the
  same convention the Reasoning, Detection, and Exposure Engines followed).
- **No changes to any existing subsystem**: Core Platform (Threat
  Intelligence, Knowledge Intelligence, Investigation, Reasoning Engine v1.0),
  Detection Engineering v1.0 + the Detection Knowledge Library, the
  Operational Dashboard, the AI layer, or the frozen Exposure Engine v1.0.
- **Testing:** 75 new offline tests (`backend/tests/identity/`) — models,
  the provider ABC's stub/health/safe-lookup behavior, registry routing,
  config, the in-memory cache (including TTL expiry), aggregation, the service
  (empty registry + fake providers, including one that raises, plus a
  determinism check), and the API endpoint. Backend suite: **2,201 passed, 1
  skipped** (was 2,126). Frontend: **101 tests** (was 98; +3 for the identity
  client); build clean with the new `/identity` route. Ruff/mypy (strict)
  clean across 146 source files.
- **Docs:** `docs/architecture/PHASE-6.0-IDENTITY-FRAMEWORK.md` (framework
  design, provider interface, registry design, canonical models, dependency
  direction, known limitations, future provider roadmap).

Have I Been Pwned, Microsoft Entra ID / Azure AD, Okta, JumpCloud, Google
Workspace, Active Directory, Microsoft Defender for Identity, CrowdStrike
Identity, any OAuth2/LDAP integration, and `InvestigationSummary` integration
all remain explicitly deferred to later, unstarted phases (Phase 6.1+).

### Added — Phase 5.0: Exposure Intelligence Framework (architecture only)

- **New framework** (`threatlens.exposure`) — the first milestone of
  ThreatLens v2.0. Answers "where is this entity exposed" (open ports,
  certificates, passive DNS, hosting, subdomains, breaches, paste sites, …),
  never "is this malicious" — a separate framework from Threat Intelligence
  at every layer (no shared models, no shared registry, no import in either
  direction). Mirrors the proven `providers/` framework shape: closed
  vocabularies, frozen Pydantic models, an `ExposureProvider` ABC, a
  registry that registers and routes, a pure `merge_findings` aggregation
  function, and `ExposureService`.
- **Zero concrete providers.** Every code path (registration, routing,
  aggregation, the service) is real and tested against an empty registry —
  `ExposureService.investigate()` naturally returns a well-formed, empty
  `ExposureSummary` through the same aggregation path a future provider
  will use unmodified. Cache (`ExposureCache` + an in-memory default) and
  config (`ExposureConfig.from_env()`) are interfaces/settings only — no
  Redis, no persistence, nothing wired in yet.
- **`GET /api/v1/exposure`** — a pure readiness probe (`status`, `message`,
  `framework_version`, `providers_registered`), not integrated into
  `/investigate`. A new placeholder page at **`/exposure`** shows the same
  three fields; the Investigation Workspace is unchanged.
- **No changes to any frozen v1.x subsystem**: Core Platform (Threat
  Intelligence, Knowledge Intelligence, Investigation Engine, Reasoning
  Engine v1.0), Detection Engineering v1.0 (all generators + the Detection
  Knowledge Library), or the Operational Platform (Operational Dashboard,
  Investigation Workspace, Detection Workspace).
- **Testing:** 66 new offline tests (`backend/tests/exposure/`) — models,
  the provider ABC's stub/health/safe-lookup behavior, registry routing,
  config, the in-memory cache (including TTL expiry), aggregation, the
  service (empty registry + fake providers, including one that raises), and
  the API endpoint. Backend suite: **1,683 passed, 1 skipped**. Ruff/mypy
  clean.
- **Docs:** `docs/architecture/PHASE-5.0-EXPOSURE-FRAMEWORK.md` (framework
  design, provider interface, registry design, summary model, dependency
  direction, future provider roadmap).

### Added — Phase 5.1: Shodan Exposure Provider (first concrete provider)

- **`ShodanProvider`** — the first concrete Exposure Intelligence provider,
  reporting open ports, running services, TLS certificates, hostnames/
  domains, and hosting/ASN facts for IPv4/IPv6 via Shodan's Host API. Purely
  descriptive, never a score or verdict. Registered by default
  (`SHODAN_ENABLED=true`); a missing `SHODAN_API_KEY` yields a structured
  `unauthorized` finding, never an exception.
- **Reuses `providers/http.py`'s `HttpClient`** — a disclosed, narrow
  exception to Phase 5.0's provider/exposure import isolation (see
  `docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md`); no file under
  `providers/` was modified.
- **`GET /api/v1/exposure`** gains an optional `?value=` query param that
  runs a real lookup (detect → route → aggregate) and returns the merged
  `ExposureSummary`, plus per-provider health (`providers: [...]`). With no
  `value`, behavior is unchanged from Phase 5.0. A disabled or unconfigured
  provider still returns `200` with a well-formed empty/failed summary.
- **In-memory caching** of definitive (`ok`/`not_found`) Shodan lookups (one
  hour TTL, Phase 5.0's `InMemoryExposureCache` — no Redis, no database);
  transient failures and auth errors are never cached.
- **`/exposure` page rebuilt**: Provider Status (framework version, provider
  count, per-provider health) plus a search box; results render per-provider
  with assets/evidence/references when configured, a friendly message when
  disabled/unconfigured — never a crash. The Investigation Workspace is
  unchanged.
- **No changes to any frozen v1.x subsystem** (Core Platform, Detection
  Engineering, Operational Platform) and no changes to any file under
  `providers/`.
- **Testing:** 39 new/updated offline tests (`test_shodan_provider.py` plus
  registry/service/API updates for the now-non-empty default registry) — all
  network mocked via `httpx.MockTransport`, zero real API key or Internet
  access required. Exposure suite: **105 tests** (was 66). Backend suite:
  **1,722 passed, 1 skipped** (was 1,683). Frontend: **98 tests** (was 92).
  Ruff/mypy clean across 133 source files. Browser-verified end-to-end
  (Playwright) for both the unconfigured and configured-with-results paths.
- **Docs:** `docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md`.

Censys, GreyNoise, HIBP, SecurityTrails, IntelligenceX, BinaryEdge, FOFA,
CriminalIP, LeakIX, domain/email exposure, and `InvestigationSummary`
integration remain explicitly deferred to later, unstarted phases.

### Added — Phase 5.2: Censys Exposure Provider (framework validation)

- **`CensysProvider`** — the second concrete Exposure Intelligence provider,
  reporting open ports, services, TLS certificates, reverse-DNS hostnames,
  and hosting/ASN facts for IPv4/IPv6 via Censys Search's v2 Host view.
  Authenticates with an API ID + Secret pair (`CENSYS_API_ID`/
  `CENSYS_API_SECRET`) over HTTP Basic auth; missing/partial credentials
  yield a structured `unauthorized` finding, never an exception.
- **Validates the framework scales to multiple providers with zero
  architectural change**: `build_default_registry()` gained one
  `register()` line; `ExposureService`, `merge_findings()`, the
  `GET /api/v1/exposure` endpoint, and the `/exposure` frontend page are all
  byte-for-byte unmodified. A single IPv4 lookup now routes to and merges
  both Shodan and Censys, in deterministic order (existing priority-then-
  name tiebreak — no new ordering logic).
- **Same provider-local in-memory caching** as Shodan (one hour TTL,
  definitive results only).
- **Test isolation fix** (`tests/exposure/conftest.py`, new): clears
  provider-credential env vars before every exposure test, so the suite's
  outcome never depends on what a local `backend/.env` happens to contain.
- **No changes to any frozen v1.x subsystem**, no changes to any file under
  `providers/`, and **no frontend file changes at all** — browser-verified
  that the existing Phase 5.1 page/components already render a second
  provider correctly.
- **Testing:** 36 new/updated tests (32 in `test_censys_provider.py`, plus
  registry/service/API updates and the new conftest). Exposure suite:
  **141 tests** (was 105). Backend suite: **1,758 passed, 1 skipped** (was
  1,722). Frontend: **98 tests, unchanged**. Ruff/mypy clean across 134
  source files.
- **Docs:** `docs/architecture/PHASE-5.2-CENSYS-PROVIDER.md`.

GreyNoise, SecurityTrails, FOFA, LeakIX, BinaryEdge, CriminalIP, HIBP,
IntelligenceX, domain/email exposure, and `InvestigationSummary` integration
remain explicitly deferred to later, unstarted phases.

### Changed — Phase 5.2.1: Censys Personal Access Token migration

- **`CensysProvider` now supports Censys's current Platform API** via
  `CENSYS_PERSONAL_ACCESS_TOKEN` (`Authorization: Bearer`), preferred over
  the original legacy `CENSYS_API_ID`/`CENSYS_API_SECRET` Basic-auth pair,
  which remains fully supported for backward compatibility. Auth mode is
  resolved once at construction: PAT → legacy pair → not configured.
- **Health semantics for Censys changed**: no credentials configured at all
  now reports `DISABLED` ("not set up") instead of `DEGRADED` ("configured
  but rejected"). `ShodanProvider` is unchanged (still `DEGRADED`) — a
  deliberate, disclosed asymmetry scoped to this migration, not applied
  project-wide.
- Response parsing now defensively unwraps either the legacy flat `result`
  shape or a Platform-style `result.host` nesting; the exact Platform API
  endpoint/response shape is a best-effort mapping, not verified against a
  live account (this sandbox's egress policy blocks third-party API hosts).
- No new files; `tests/exposure/conftest.py` extended to also clear
  `CENSYS_PERSONAL_ACCESS_TOKEN`. 14 new tests (46 in
  `test_censys_provider.py`, 151 in the exposure suite, 1,768 backend
  tests total). No frontend changes. No changes to any frozen v1.x
  subsystem or to any file under `providers/`.

### Added — Phase 5.3: GreyNoise Exposure Provider (framework re-validation)

- **`GreyNoiseProvider`** — the third concrete Exposure Intelligence
  provider, reporting internet-noise/business-service classification for
  IPv4 (only) via GreyNoise's Context API. A genuinely different kind of
  fact than Shodan/Censys's scan-surface data — reputation/context, not open
  ports — but still purely descriptive: GreyNoise's own classification is
  reported as a quoted, attributed third-party statement
  (`"GreyNoise classification: malicious"`), never a ThreatLens-computed
  verdict. Authenticates with a single API key (`GREYNOISE_API_KEY`) sent as
  GreyNoise's own `key` header convention; a missing key yields a structured
  `unauthorized` finding, never an exception. Contributes no assets (no
  ports/certs/hostnames) — every finding is evidence-only, a shape the
  canonical model already supported.
- **New canonical vocabulary value**: `ExposureCapability.INTERNET_NOISE` —
  the framework's first new model addition since Phase 5.0, added because no
  existing capability describes "internet-scanning background noise or a
  recognized business service." Purely additive; no existing value's meaning
  changed.
- **Re-validates the framework scales to N providers with zero architectural
  change**: `build_default_registry()` gained one more `register()` line;
  `ExposureService`, `merge_findings()`, the `GET /api/v1/exposure` endpoint,
  and the `/exposure` frontend rendering are all byte-for-byte unmodified. A
  single IPv4 lookup now routes to and merges all three providers, in
  deterministic order (`censys` < `greynoise` < `shodan`, existing
  priority-then-name tiebreak — no new ordering logic).
- **Same provider-local in-memory caching** as Shodan/Censys (one hour TTL,
  definitive results only).
- **Health semantics follow Shodan's original convention, not Censys's PAT
  migration**: a missing API key reports `DEGRADED`, not `DISABLED` — the
  `DISABLED`-on-missing-credentials distinction stays scoped to the Censys
  migration that explicitly requested it.
- **Frontend**: one type-parity addition (`ExposureCapability` gains
  `"internet_noise"` in `lib/api.ts`, mirroring the backend enum) and a
  one-line copy fix to the exposure page's static provider-scope caption;
  no rendering-logic change. Browser-verified with a mocked three-provider
  response that the existing generic provider-status and finding-card
  rendering (including GreyNoise's zero-assets, evidence-only shape) needs
  no component changes.
- **No changes to any frozen v1.x subsystem**, and no changes to any file
  under `providers/` (only imports `providers/http.py`'s `HttpClient`, the
  same disclosed exception Shodan/Censys already established).
- **Testing:** 36 new tests (`test_greynoise_provider.py`), plus
  registry/service/API updates for three default providers. Exposure suite:
  **187 tests** (was 151). Backend suite: **1,804 passed, 1 skipped** (was
  1,768). Frontend: **98 tests, unchanged**. Ruff/mypy clean across 135
  source files.
- **Docs:** `docs/architecture/PHASE-5.3-GREYNOISE-PROVIDER.md`.

SecurityTrails, FOFA, LeakIX, BinaryEdge, CriminalIP, HIBP, IntelligenceX,
domain/email exposure, and `InvestigationSummary` integration remain
explicitly deferred to later, unstarted phases (Phase 5.4+).

### Added — Phase 5.4: Exposure Engine v1.0 (validation & freeze)

- **New validation/freeze suite** (`tests/exposure_validation/`), mirroring
  the Reasoning (Phase 3.15) and Detection Engine (Phase 4.5) freezes: a
  153-scenario corpus (12 realistic category labels × every provider-matrix
  combination, plus 9 standalone edge cases) driven through the real,
  unmodified `ExposureRegistry` + `ExposureService` via a controllable fake
  provider — no network, no live account, no HTTP mocking.
- **0 invariant violations** across all 153 scenarios: routing, concurrent
  merge/ordering, statistics, no duplicate references/evidence/assets,
  serialization round-trips, and the frontend/API key contract. A
  representative subset additionally verified through the real
  `GET /api/v1/exposure` HTTP endpoint.
- **Determinism verified for all 153 scenarios** (content-level, excluding
  `metadata.generated_at` — the one wall-clock field
  `ExposureService.investigate()` produces with no injectable clock, the
  same documented exclusion Reasoning/Detection already apply to their own
  `generated_at`).
- **Golden regression** (`tests/exposure_validation/golden.json`), CI-gated
  in the same job as the reasoning/IOC/detection/knowledge-library goldens.
- **Performance benchmarked**: `investigate()` scaling (1-100 lookups, no
  bottleneck — per-lookup cost *improves* at scale as fixed event-loop
  overhead amortizes), cache effectiveness (16.6× cold/warm speedup via the
  real `InMemoryExposureCache`), and `merge_findings` scaling in isolation.
  No optimization was performed (none is justified).
- **Architecture reviewed**: provider/model/registry/cache/service
  abstractions all confirmed sufficient — **zero redesign**, zero new
  providers, zero new canonical models.
- **Frozen**: `EXPOSURE_FRAMEWORK_VERSION` moves from `"0.1.0"` to `"1.0"` —
  the only production-code change in this entire phase.
- **Testing:** 322 new tests. Backend suite: **2,126 passed, 1 skipped**
  (was 1,804). Frontend: **98 tests, unchanged** — no frontend file touched.
  Ruff/mypy clean across 135 source files (unchanged count).
- **Docs:** `docs/architecture/PHASE-5.4-EXPOSURE-ENGINE-V1.md`.

**GO — Exposure Intelligence is frozen at v1.0.** Future provider additions
follow the same contract as the Reasoning/Detection freezes: regenerate the
golden, bump the version, document the change. Phase 5.5 and beyond
(additional providers, domain/email exposure, `InvestigationSummary`
integration) remain explicitly out of scope until separately started.

## [1.1.1] — 2026-07-04

Patch release: operational tooling and frontend presentation refinements, no
change to any frozen engine's behavior or output contract, no new
investigation/detection capability. Kept at patch rather than minor because
nothing here is analyst-facing capability — it's admin-only observability
plus pure presentation restructuring of data the UI already had.

### Added — Operational Dashboard v1

- **New read-only subsystem** (`threatlens.system`) for administrators and
  developers: system health, API consumption, and configuration status. It is
  strictly downstream and isolated — it never calls a provider, runs an
  investigation, generates a detection, or invokes the AI layer; it only reads
  already-computed response objects and the existing health checks. No change
  to the Investigation Engine, the frozen Reasoning Engine, the Detection
  Engine, the Detection Knowledge Library, or the AI layer's behavior or API
  contracts.
- Three new endpoints under `/api/v1/system`: `GET /health` (per-service
  Healthy/Degraded/Offline/Disabled + overall rollup, reusing the Phase 3.17
  health checks), `GET /usage` (in-memory, process-local request/latency
  counters per provider, the AI layer, Detection Engineering, Detection
  Knowledge, and investigations — reset on restart, no database), and
  `GET /config` (configured/enabled booleans only — never a key, token,
  secret, or credential-bearing URL).
- **New frontend page** at `/dashboard` (separate from the Investigation
  Workspace) with three tabs — System Health, API Consumption, Configuration —
  reachable from the existing status pill. Reuses the app's dark theme and
  existing shared presentation primitives.

### Changed — Frontend UI Refinements

- **Detection Workspace v1**: restructured the Detection Engineering and
  Detection Knowledge panels into a progressive-disclosure Language → Rule →
  Rule Details drill-down, replacing one long list of full rule bodies.
  Presentation only — no change to detection generation, matching, or scoring.
- **Investigation Workspace v2**: grouped Overview, Threat Intelligence, Key
  Attributes, Relationships, and References under a "Supporting Investigation
  Data" zone below "Investigation Results," with a compact Overview summary,
  categorized Key Attributes, and grouped Relationships/References cards.
  Presentation only — no change to investigation data or logic.
- **Tag Presentation v1**: large tag lists (Key Attributes and per-provider
  Tags) now preview ~20 with a "Show all" disclosure instead of rendering
  every tag unconditionally. Presentation only — tag content, order, and
  count unchanged.

## [1.1.0] — 2026-07-03

**Detection Engineering v1.0**: a complete, deterministic detection subsystem
built downstream of the frozen Investigation & Reasoning Engines, delivered
across Phases 4.0–4.6 and validated end-to-end (140-scenario detection corpus,
golden regression across nine generators, 1,581 backend tests, linear
performance scaling). It never modifies the Investigation Engine, the frozen
Reasoning Engine (`ENGINE_VERSION` unchanged at `"1.0"`), findings, confidence,
or recommendations. Detection Engineering is itself frozen at
`DETECTION_ENGINE_VERSION = "1.0"` as of Phase 4.5.

### Phase 4.6 — Detection Knowledge Library

- **New downstream, read-only subsystem** (`threatlens.detection_library`) that
  discovers, normalizes, indexes, searches, and recommends **community**
  detection content. It never generates detections and **does not modify the
  frozen Detection Engine v1.0** (generators, identities, metadata, and the
  `/detections` contract are untouched). A *generated* detection and a
  *community* detection are kept explicitly separate and never merged.
- **Seven community sources** (bundled offline seed, fully attributed): SigmaHQ,
  YARA-Rules, Emerging Threats Open, Elastic Detection Rules, Microsoft Sentinel,
  Cisco Talos, Splunk Security Content. A single configurable
  `BundledCommunityProvider` implements the read-only `CommunityProvider`
  interface from a `RuleSource` descriptor + seed file, so a new repository plugs
  in as data — no framework change. A future live-fetch provider is a subclass.
- **Deterministic normalization** (`normalize_record`): content-addressed ids,
  real ATT&CK/IOC extraction from rule text (conservative domain handling that
  rejects rule-DSL tokens and vendor/reference hosts), and severity/category/
  platform inference — into one canonical `CommunityRule` per repository.
- **Offline indexed library + search** by IOC, MITRE technique, threat actor,
  malware family, rule name, tags, rule id, language, repository, severity, and
  platform (AND-combined, stable order).
- **Deterministic matching & similarity** — 0–100 weighted set-overlap similarity
  (IOC 38 · MITRE 24 · malware 12 · actor 8 · category 8 · tags 6 · platform 4)
  plus a coverage metric, classifying each rule as exact / partial / related.
  **No AI, no embeddings, no fuzzy matching**; `recommend` inherits `generated_at`
  from the summary and reads no clock.
- **Synchronization separate from investigation** — `synchronize` snapshots to a
  `LibraryCache` (incremental diff, per-source version hashes, atomic write,
  tolerant read, invalidate, staleness TTL). Offline-first: with no cache
  configured the service serves the bundled seed; the investigation path never
  depends on GitHub.
- **Licensing preserved** — repository, author, license, version, and URL are
  never dropped and content is never rewritten. Redistribution follows the
  license: permissive/copyleft bodies are shown; Elastic's restricted
  (Elastic-2.0) bodies are withheld (metadata + attribution + link only) with a
  documented note.
- **API:** `POST /api/v1/detection-knowledge/recommend` (summary → ranked
  community matches) and `GET /api/v1/detection-knowledge/search`. Both read-only,
  offline, deterministic.
- **Frontend:** a new **Detection Knowledge** card, rendered separately from the
  generated Detection Engineering card — repository, language, similarity,
  coverage, MITRE, license, author, last-updated, view/download (download gated on
  license). New `recommendCommunityDetections`/`searchCommunityDetections` client
  + `lib/knowledge.ts` helpers.
- **Testing:** 74 offline DKL tests (normalization, search, similarity, matching,
  licensing, versioning, cache, determinism, golden regression) added to the CI
  golden-regression job; +11 frontend tests. Backend suite: **1,580 passing**.
  Linear performance (per-rule cost ≈1.1× from 18→1000 rules).
- **Docs:** `docs/architecture/PHASE-4.6-DETECTION-KNOWLEDGE-LIBRARY.md`
  (architecture, normalization/matching/similarity/caching design, licensing,
  testing & performance).

### Phase 4.5 — Detection Engine v1.0 (Validation & Freeze)

- **Detection Engineering frozen at v1.0** (`DETECTION_ENGINE_VERSION = "1.0"`).
  No new formats, generators, or AI — this phase validates the whole subsystem
  and locks it. Future generator-output changes must regenerate the golden
  snapshot, bump the version, and document the change (same contract as the
  Reasoning Engine freeze).
- **140-scenario validation corpus** (`backend/tests/detection/corpus.py`)
  covering every supported IOC subject (ip/ipv6/domain/url/md5/sha1/sha256/
  process/registry/powershell) × severities × confidence bands × ATT&CK state,
  plus multi-finding, duplicate, conflicting, multi-IOC, unsupported, malformed,
  informational, and empty cases. Every one of the nine generators is exercised.
- **Freeze invariants** asserted per scenario (`harness.py`): determinism,
  timestamp-independent content-addressed identity, unique ids, provenance
  (`metadata.detection_id == artifact.id`, finding-id subset), ATT&CK-in-rule,
  structural validity, JSON round-trip, and the frontend/API key contract —
  **0 violations**.
- **Parser-level validators for all nine languages** (`validate.py`), unit-tested
  (`test_validators.py`), plus an **optional** native layer (`yara-python` /
  `pysigma`) used only when installed — **no external validator is required in
  CI**.
- **Golden regression** (`golden.json`) snapshots every scenario × generator and
  is now CI-gated (`pytest tests/detection` added to the golden-regression job);
  drift fails CI until `THREATLENS_UPDATE_GOLDEN=1` regeneration.
- **Performance benchmark** (`perf.py`, smoke-tested): generation scales
  **linearly** (per-rule cost varies 1.28× from 1→1000 findings; memory linear).
  Largest contributor is the Chronicle YARA-L generator. No optimization needed.
- **Consistency fix:** the Sigma generator now also emits `detection_id` and
  `rule_id` metadata keys (previously only `sigma_id`) so all nine generators
  share the provenance contract. **Metadata only — Sigma rule content and its
  golden are unchanged.**
- **No regressions:** six stale exact-equality test assertions from Phases
  4.2–4.4 (e.g. `registry.languages == (SIGMA,)`, `pkg["languages"] ==
  ["sigma"]`, `artifacts[0]`) were updated to membership / by-language selection
  now that nine generators are registered. Backend suite: **1,506 passing** (0
  failed, 1 optional-native skip).
- **Docs:** `docs/architecture/PHASE-4.5-DETECTION-ENGINE-V1.md` (validation
  report, architecture review, performance results, corpus summary, readiness
  score, GO recommendation).

### Phase 4.4 — SIEM Detection Generators

- **Five platform-native SIEM generators** (`detection/future/splunk.py`,
  `sentinel.py`, `elastic.py`, `chronicle.py`, `qradar.py`, sharing a new pure
  `_siemcommon.py`) — deterministic `DetectionGenerator`s emitting **Splunk SPL,
  Microsoft Sentinel KQL, Elastic ES|QL, Google Chronicle YARA-L, and IBM QRadar
  AQL**. Registered in `build_default_registry()` (nine generators total); the
  engine and `POST /api/v1/detections` are unchanged.
- **Native syntax, not Sigma-converted.** Log-observable subjects only — IP,
  domain, URL, file hash, process, registry key, PowerShell command (and their
  ATT&CK context). Never for CWE/CAPEC, actor/technique-only, informational, or
  unsupported findings.
- **Full provenance** in every detection (artifact metadata + query comment /
  YARA-L `meta:`): detection id, generator, platform, finding ids, severity,
  confidence, MITRE mappings, IOC type/value, generated timestamp, engine version.
- **Deterministic** — identical summary → identical query; identifiers hash only
  stable values (no randomness, no UUIDs). The timestamp/detection-id live in
  metadata only and are excluded from identity, keeping ids and the package id
  timestamp-independent.
- **Parser-level validation** (`validator: threatlens-parser`) since native
  validators are unavailable: required-token and brace-balance checks per language.
- Added `DetectionLanguage` values `elastic_esql`, `chronicle_yara_l`,
  `qradar_aql`.
- **Frontend:** the panel renders any artifact; added native export extensions
  (`.spl`, `.kql`, `.esql`, `.yaral`, `.aql`) so analysts can export all nine
  formats.

### Phase 4.3 — Network Detection Generators (Suricata & Snort)

- **Two network generators** (`detection/future/suricata.py`, `snort.py`, sharing
  a new pure `_netrules.py`) — deterministic `DetectionGenerator`s emitting
  **Suricata** and **Snort** IDS/IPS rules. Registered in
  `build_default_registry()`; the engine and `POST /api/v1/detections` are
  unchanged and may now return Sigma + YARA + Suricata + Snort artifacts.
- **Network-observable only.** IP → `alert ip … -> <ip>`; domain → Suricata
  `dns.query` / Snort HTTP `http_header` content; URL → HTTP host + URI content
  (non-safe bytes encoded as `|HH|`). Never for hashes, CVE/CWE/CAPEC,
  actor/technique-only, file-only, or informational findings — no rule beats a
  weak/speculative one; rules never contain a file hash.
- **Complete rules:** `msg`, `sid`, `rev`, `classtype`, `metadata`,
  `reference`, `priority`, `flow` (HTTP), `content` (deterministic). Severity
  copied to priority; same-IOC findings merged.
- **Deterministic SID allocation:** `sid = 1_000_000 + (sha256(engine|kind|value)
  mod 9_000_000)` — stable per IOC, distinct per engine, in the custom SID range;
  no randomness, no UUID4. `rule_id`/`detection_id` stable and
  timestamp-independent. Full traceability in every rule's metadata.
- **Frontend:** the panel already renders any artifact; added a `.rules` download
  extension. A network IOC now shows complementary Sigma + Suricata + Snort rules.

### Phase 4.2 — YARA Detection Generator

- **Second detection generator** (`detection/future/yara.py`) — a pure,
  deterministic `DetectionGenerator` that emits **YARA** rules from findings.
  Registered in `build_default_registry()` next to Sigma; the engine and
  `POST /api/v1/detections` are unchanged and now return Sigma **and** YARA
  artifacts when applicable.
- **File-hash only.** YARA detects files, so rules are emitted only for
  MD5/SHA1/SHA256 findings via the `hash` module (`hash.sha256(0, filesize) ==
  …`, `filesize < 100MB`). Never for IPs, domains, URLs, CVE/CWE/CAPEC,
  actors/techniques, malware-family *names*, informational findings, or malformed
  hashes — no rule beats a weak/IOC-style rule. Rules never contain a network IOC.
- **Complete, traceable rules:** `import "hash"`, rule name, full `meta:`
  (description, author, date, reference, `finding_ids`, `rule_id`,
  `detection_id`, source, `threatlens_version`, severity, hash, `mitre_attack`),
  and condition. Severity copied from the finding; same-hash findings merged.
- **Deterministic identity:** rule name/`rule_id` hash only the file hash;
  artifact/package ids exclude the `date` (no timestamps, no randomness, no
  UUID4) — stable across executions.
- **Frontend:** the panel already renders any artifact; added a `.yar` download
  extension. A file-hash investigation now shows complementary Sigma + YARA rules.

### Phase 4.1 — Sigma Detection Generator

- **First concrete detection generator** (`detection/future/sigma.py`) — a pure,
  deterministic `DetectionGenerator` that converts `InvestigationSummary`
  findings into minimal, readable **Sigma** rules. Registered in
  `build_default_registry()`; the engine and `POST /api/v1/detections` are
  unchanged and now return Sigma artifacts.
- **Consumes only `Finding` objects** — never provider responses, raw TI,
  reputation, WHOIS, or NVD/MITRE JSON. No AI, no network, no wall clock.
- **Mapping:** IPv4/IPv6 → firewall `dst_ip`; domain → dns `query`; URL → proxy
  `c-uri|contains`; file hash → process_creation `Hashes|contains`. Severity is
  copied into the Sigma `level` (never recomputed). CWE/CAPEC/CVE, informational
  findings, and knowledge subjects (techniques/actors/malware) do not yield a
  standalone rule; their ATT&CK context enriches IOC rules' tags/references.
- **Traceability:** every rule carries `finding_ids` in metadata and cites the
  finding id(s), subject, MITRE ATT&CK (when present), and evidence sources.
- **Deterministic identity:** Sigma `id` is a UUIDv5 of the IOC; artifact/package
  ids hash only stable values (no timestamps, no randomness) — the `date` field
  is present but excluded from identity. Findings on the same IOC are merged
  (duplicate suppression).
- **Frontend:** the Detection Engineering panel now renders artifacts — language,
  title, severity, category, finding IDs, the Sigma YAML, and copy/download
  buttons (read-only).

### Phase 4.0 — Detection Engineering Framework

- **Detection Engineering Framework** (`backend/src/threatlens/detection/`) — a
  new downstream, deterministic consumer of the frozen `InvestigationSummary`. A
  pure `generate(summary) → DetectionPackage` engine converts findings into
  reusable detection content. **Framework only:** no generators, no Sigma, no
  YARA, no AI, no rule generation (those arrive in later phases).
- **Canonical models** (all frozen): `DetectionPackage`, `DetectionArtifact`,
  `DetectionMetadata`, `DetectionReference`, `DetectionTarget`,
  `DetectionTemplate`, `DetectionValidation`, plus enums (language, category,
  severity, capability, validation status).
- **Content-addressed identity** — deterministic `det_`/`pkg_` ids hashing only
  stable values; the package id is timestamp-independent, and `generated_at` is
  inherited from the summary (the engine never reads the wall clock).
- **Registry & extension points** — `DetectionRegistry` (empty default) with
  `DetectionGenerator` and `DetectionValidator` ABCs as the seams future
  Sigma/YARA/Suricata/Snort/Splunk/Sentinel/Elastic/CrowdStrike generators plug
  into; template infrastructure + `apply_template`.
- **API** — `POST /api/v1/detections` (InvestigationSummary → DetectionPackage;
  empty package in this phase).
- **Frontend** — `DetectionPackage` types + a placeholder Detection Engineering
  panel ("No detection artifacts generated.").
- The Reasoning Engine, detection (entity) engine, providers, AI reasoning, and
  investigation pipeline are untouched; detection is strictly downstream and
  never alters findings, confidence, severity, priority, recommendations, or
  relationships.

### Phase 3.17 — Operational Readiness & Health Monitoring

- **Read-only health & version endpoints** — `GET /health` (liveness),
  `GET /ready` (readiness, `503` when the deterministic core is down),
  `GET /health/providers` (TI configuration, no network / no quota),
  `GET /health/knowledge` (offline reference-dataset status & versions),
  `GET /health/ai` (the only endpoint that may touch the network — a lightweight
  Ollama reachability probe, never a generation), and `GET /version`. Mounted at
  the root (infra probes) and under `/api/v1` (frontend). Every check is
  side-effect-free and never runs an investigation. (`backend/src/threatlens/api/health.py`)
- **Frontend system-status indicator** — a passive status pill driven by
  `GET /health` and `GET /health/ai`; it can never block or alter the app.
- The frozen Reasoning Engine, detection engine, providers, and investigation
  pipeline are untouched — these endpoints only *report* on them.

## [1.0.0] — 2026-07-02

First stable release: **ThreatLens Core Platform v1.0**. Everything below was
delivered across Phases 0–3.16 and validated end-to-end (100-IOC regression
corpus, 1,177 backend tests, golden snapshots, GO recommendation at 9.2/10).

### Phase 0 — Architecture

- Search-first platform architecture: every capability begins with entity
  detection; IOC analysis is one capability of search, not the product.
  (`docs/architecture/PHASE-0-ARCHITECTURE.md`)

### Phase 1 — Detection, Providers & Investigation

- **Universal Entity Detection Engine** — deterministic, offline classification
  of arbitrary input into 21 entity types with normalization (incl. defanged
  indicators), confidence, and validation status.
- **FastAPI API** — `POST /api/v1/detect`, `POST /api/v1/investigate`,
  `GET /api/v1/health`; strict input validation (422 on empty/blank/oversized).
- **Threat Intelligence Provider Framework** — metadata/registry/router,
  canonical vendor-neutral `IntelligenceResult`, shared HTTP client with retry
  and typed errors. Providers: **MalwareBazaar, URLhaus, AbuseIPDB, AlienVault
  OTX**. Failures are values — a failed provider never fails an investigation.
- **Aggregation Engine** — merges per-provider results into one attributed
  `AggregatedResult` (de-duplicated evidence/relationships/references, per-item
  source attribution, namespaced metadata).
- **Investigation Service** — runs TI and knowledge providers concurrently in a
  single gather, aggregating each framework independently.
- **Next.js Investigation Workspace** — search box, entity overview, provider
  cards, relationships, references (Vercel-deployable; detection API as a
  Vercel Python function).

### Phase 2 — Knowledge Intelligence

- **Reference Provider Framework** — a parallel framework for offline,
  versioned knowledge sources returning the same canonical result model.
- **Bundled knowledge providers** (no network, no keys): **MITRE ATT&CK**
  (techniques, groups, software), **NVD/CVE** (CVSS, severity, CWE links),
  **CWE** (weaknesses, CAPEC links), **CAPEC** (attack patterns, ATT&CK links).
- Architecture review (Phase 2.5) incl. an NVD date-parsing fix.

### Phase 3 — Investigation Intelligence

- **Reasoning Engine v1.0** (Phases 3.1a–3.1d, frozen in 3.15) — a pure,
  deterministic pipeline behind one entry point `reason()`:
  - weighted evidence assembly (authority × base weight × freshness; provider
    reputations lifted into evidence),
  - five typed finding rules with deterministic merge and **content-addressed
    finding IDs** (`fnd_` + sha256),
  - four-factor explainable confidence (authority 0.35 · agreement 0.25 ·
    corroboration 0.25 · freshness 0.15) with contested capping and an
    echo-chamber guard (authority *families*),
  - five recommendation rules with dedupe, cross-finding merge,
    conflict resolution, and a priority-ordered rollup with finding provenance,
  - optional `InvestigationContext` that affects **priority only**,
  - additive `investigation_summary` on `/investigate`.
- **Findings UI** (3.1e) — assessment headline, priority-ordered recommendation
  rollup, expandable finding cards with per-factor confidence breakdowns.
- **Engine validation & freeze** (3.15) — 58-scenario regression benchmark with
  golden snapshot, performance harness (~0.4 ms end-to-end), API contract
  tests, and the v1.0 reference architecture document.
- **AI Explanation Layer** (3.2) — optional, strictly downstream narration:
  `AIProvider` abstraction with **Ollama** as first provider, deterministic
  `PromptBuilder` consuming only `InvestigationSummary` (untrusted-data
  delimiting + injection rules), **code-enforced grounding**, structured
  `disabled`/`unavailable`/`error` responses, `POST /api/v1/explain`, and a
  collapsed-by-default frontend card. Off by default; the platform behaves
  identically without a model.
- **Platform validation** (3.16) — 100-IOC end-to-end regression corpus
  (detection → routing → aggregation → reasoning → contract → determinism →
  AI grounding/degradation), golden `InvestigationSummary` snapshot, and an
  auto-generated validation report. Result: 0 failures, 0 crashes.

### Quality gates locked in CI

- Ruff (lint) · mypy `--strict` (80 source files) · 1,177 backend tests ·
  9 frontend tests · frontend production build · golden regression
  (155 pinned investigation summaries; drift fails the build).

[1.0.0]: https://github.com/Otomen1/ThreatLens/releases/tag/v1.0.0
