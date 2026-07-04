# Changelog

All notable changes to ThreatLens are documented here. The project follows
[Semantic Versioning](https://semver.org/) and (from v1.0.0 on) the
[Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

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
