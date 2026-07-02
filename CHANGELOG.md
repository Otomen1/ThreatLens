# Changelog

All notable changes to ThreatLens are documented here. The project follows
[Semantic Versioning](https://semver.org/) and (from v1.0.0 on) the
[Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

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
