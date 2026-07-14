# ThreatLens

**A search-first, deterministic threat-intelligence and investigation platform.**

[![CI](https://github.com/Otomen1/ThreatLens/actions/workflows/ci.yml/badge.svg)](https://github.com/Otomen1/ThreatLens/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-1.2.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

**What is ThreatLens?**
ThreatLens is an investigation platform built around one idea: *every investigation begins with understanding the indicator.* Paste anything into the search box — an IP, domain, URL, file hash, CVE, MITRE ATT&CK technique, CWE, CAPEC, threat actor, or malware family — and ThreatLens deterministically identifies the entity, routes it to the intelligence sources that can answer for it, aggregates the evidence, and runs a deterministic reasoning engine that produces **findings, confidence, priority, and recommendations**. An optional AI layer then *explains* the result in plain language — it never produces it.

**What problems does it solve?**

- **Indicator triage is slow and manual.** Analysts pivot across half a dozen TI portals per indicator. ThreatLens federates providers behind one search box and one aggregated, attributed result.
- **Verdicts are opaque.** Most tools emit a score with no reasoning. Every ThreatLens finding carries its evidence, the rule that produced it, a four-factor confidence breakdown, and a derived priority — fully explainable, fully reproducible.
- **AI answers can't be trusted for security decisions.** ThreatLens keeps AI strictly downstream: the deterministic engine is the single source of truth, and the AI layer can only narrate it (with code-enforced grounding), never alter it.

**Who is it for?**
SOC analysts, incident responders, detection engineers, and threat-intel teams who want fast, explainable, reproducible indicator investigations — self-hosted, offline-capable, and free of black-box verdicts.

---

## Features

| Feature | Description |
|---|---|
| **Threat Intelligence** | Async, concurrent enrichment from external TI providers (AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar) with per-provider status, graceful partial failure, and attributed evidence. |
| **Knowledge Intelligence** | Offline, bundled reference knowledge: MITRE ATT&CK (techniques, groups, software), NVD/CVE, CWE, and CAPEC — no network or keys required. |
| **Reasoning Engine v1.0 (frozen)** | A pure, deterministic engine: weighted evidence assembly → typed finding rules → four-factor confidence (authority · agreement · corroboration · freshness) → derived priority → recommendation rollup. Content-addressed finding IDs; identical inputs always produce identical output. |
| **AI Explanation** | Optional, downstream narration of a completed investigation via Ollama (local LLM). Grounded in code — hallucinated findings/recommendations are dropped. Disabled by default. |
| **Detection Engineering** | A pure, deterministic downstream consumer that converts findings into a content-addressed `DetectionPackage` (`POST /api/v1/detections`). Ships **nine** generators — **Sigma**, **YARA**, **Suricata + Snort** (network), and native **SIEM** queries for **Splunk (SPL), Microsoft Sentinel (KQL), Elastic (ES\|QL), Google Chronicle (YARA-L), and IBM QRadar (AQL)** — so one investigation yields complementary detections across every format. It never alters the investigation. |
| **Detection Knowledge Library** | A separate, **read-only** downstream subsystem that discovers, normalizes, indexes, searches, and recommends **community** detections (SigmaHQ, YARA-Rules, Emerging Threats, Elastic, Microsoft, Talos, Splunk). Deterministic 0–100 similarity + exact/partial/related matching — **no AI, no embeddings** — with full provenance (repository · author · license · version · URL). Offline once synced; a *community* detection is never merged with a *generated* one. |
| **Investigation Workspace** | A Next.js analyst UI: assessment headline, priority-ordered recommendations, expandable finding cards with confidence breakdowns, provider details, relationships, and references. |
| **Saved Investigations (Phase 8.0-8.3)** | A persistence layer over completed investigations — save, load, update, delete, list, search, and filter (by status/severity/type/tag) at **`/workspace`**. Local file-backed storage, no auth, single-user. Consumes existing `InvestigationSummary`/`DetectionPackage` output verbatim; generates nothing. Distinct from the Investigation Workspace analyst UI above — see [`docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md`](docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md) for the naming disambiguation. Phase 8.1 adds a read-only, derived **Timeline** — chronological events reconstructed only from evidence that already carries an explicit timestamp; see [`docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md`](docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md). Phase 8.2 adds a read-only, derived **Evidence Graph** — entities and relationships reconstructed only from a finding's explicit `Relationship`s and correlation observations; see [`docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md`](docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md). Phase 8.3 makes that graph **interactive** — pan/zoom/fit-view, click-to-inspect, search, and filter over the same unchanged API data via React Flow; see [`docs/architecture/PHASE-8.3-INTERACTIVE-EVIDENCE-GRAPH.md`](docs/architecture/PHASE-8.3-INTERACTIVE-EVIDENCE-GRAPH.md). |
| **Provider Framework** | Plug-in architecture for both TI and knowledge providers — declare metadata, return the canonical `IntelligenceResult`, register in one place. |
| **Offline Operation** | Detection, knowledge lookup, reasoning, and the full test suite run with zero network access. External TI and AI are optional add-ons. |
| **Deterministic Reasoning** | No AI, no randomness, no wall-clock dependence in the core. Regression-locked by golden snapshots (155 pinned investigations across two suites). |

---

## Screenshots

> Screenshots live in `docs/screenshots/`. Placeholders below — capture from a local run (`uvicorn threatlens.api.app:app` + `npm run dev`).

| View | Screenshot |
|---|---|
| Home (search) | `docs/screenshots/home.png` *(placeholder)* |
| Investigation Workspace | `docs/screenshots/investigation-workspace.png` *(placeholder)* |
| Findings | `docs/screenshots/findings.png` *(placeholder)* |
| Recommendations | `docs/screenshots/recommendations.png` *(placeholder)* |
| AI Explanation | `docs/screenshots/ai-explanation.png` *(placeholder)* |
| Operational Dashboard | `docs/screenshots/operational-dashboard.png` *(placeholder)* |
| Exposure Intelligence | `docs/screenshots/exposure-intelligence.png` *(placeholder)* |

---

## Architecture

```
                       query (any indicator)
                              │
                              ▼
                ┌─────────────────────────────┐
                │  Entity Detection Engine    │   deterministic, offline
                │  (21 entity types)          │
                └──────────────┬──────────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
   ┌────────────────────────┐    ┌────────────────────────┐
   │ Threat Intelligence    │    │ Knowledge Providers    │
   │ AbuseIPDB · OTX        │    │ MITRE ATT&CK · NVD     │
   │ URLhaus · MalwareBazaar│    │ CWE · CAPEC (bundled)  │
   └───────────┬────────────┘    └───────────┬────────────┘
               └──────────────┬──────────────┘
                              ▼
                ┌─────────────────────────────┐
                │  Investigation Service      │   concurrent, partial-failure safe
                │  + Aggregation (attributed) │
                └──────────────┬──────────────┘
                               ▼
                ┌─────────────────────────────┐
                │  Reasoning Engine v1.0      │   pure · deterministic · explainable
                │  evidence → findings →      │
                │  confidence → priority →    │
                │  recommendations            │
                └──────────────┬──────────────┘
                               ▼
                     InvestigationSummary        (the immutable source of truth)
                               │
        ┌──────────────┬───────┴───────┬──────────────────┐
        ▼              ▼               ▼                  ▼
   AI Explanation   Detection      Timeline          Case Management
   (Ollama, now)    Engineering    (future)          (future)
                    (future)
```

Every downstream consumer — the AI layer today; detection engineering, timeline, and case management later — reads the immutable `InvestigationSummary`. **Nothing downstream can write back into findings, confidence, severity, priority, or recommendations.**

Deep dives: [`docs/architecture/PHASE-0-ARCHITECTURE.md`](docs/architecture/PHASE-0-ARCHITECTURE.md) (platform), [`docs/architecture/PHASE-3.15-REASONING-ENGINE-V1.md`](docs/architecture/PHASE-3.15-REASONING-ENGINE-V1.md) (reasoning engine reference), [`docs/validation/PHASE-3.16-VALIDATION-REPORT.md`](docs/validation/PHASE-3.16-VALIDATION-REPORT.md) (validation report).

---

## Supported Entity Types

| Category | Types |
|---|---|
| Network indicators | `ipv4` · `ipv6` · `domain` · `url` · `email` |
| File hashes | `md5` · `sha1` · `sha256` |
| Structured references | `cve` · `cwe` · `capec` · `mitre_technique` · `registry_key` |
| Host artifacts | `process_name` · `powershell_command` · `windows_api` · `file_name` |
| Threat knowledge (reference-backed) | `threat_actor` · `malware_family` |
| Fallbacks | `freetext` · `unknown` |

Defanged input (`hxxp://evil[.]com`) is detected and normalized. Unclassifiable input resolves to `freetext`/`unknown` — never an error.

---

## Installation

### Backend (FastAPI, Python 3.11+)

```bash
cd backend
pip install -e ".[dev]"
uvicorn threatlens.api.app:app --reload        # http://localhost:8000
```

Verify:

```bash
curl -X POST localhost:8000/api/v1/investigate \
  -H 'content-type: application/json' -d '{"query":"T1059"}'
```

### Frontend (Next.js 16, Node 20+)

```bash
cd frontend
npm ci
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 npm run dev   # http://localhost:3000
```

Production: `npm run build && npm start`. The frontend also deploys to Vercel (see `frontend/vercel.json`; the detection API ships as a Vercel Python function via `frontend/api/index.py`).

### Ollama (optional — AI explanations)

```bash
# install Ollama (https://ollama.com), then:
ollama pull qwen3:4b
export AI_ENABLED=true          # AI is OFF by default
uvicorn threatlens.api.app:app
```

ThreatLens functions identically without Ollama — the AI card simply reports "AI explanation unavailable." See **[AI Setup](#ai-setup)** below for the full five-minute guide, model recommendations, and troubleshooting.

### Docker

Container packaging (single-node `docker-compose`: API + frontend + reverse proxy) is planned alongside the deployment-hardening milestone and is not part of v1.0.0. The platform runs today via the backend/frontend steps above.

### Configuration

```bash
cp backend/.env.example backend/.env    # then fill in provider keys (all optional)
```

---

## Configuration Reference

All variables are optional — with none set, ThreatLens runs fully offline (knowledge + reasoning only).

### Backend — threat-intelligence providers

| Variable | Purpose |
|---|---|
| `ABUSE_CH_AUTH_KEY` | Shared [abuse.ch](https://auth.abuse.ch) Auth-Key used by MalwareBazaar and URLhaus. |
| `MALWAREBAZAAR_AUTH_KEY` | Optional per-provider override of the shared abuse.ch key. |
| `URLHAUS_AUTH_KEY` | Optional per-provider override of the shared abuse.ch key. |
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com) key — IPv4/IPv6 reputation. |
| `OTX_API_KEY` | [AlienVault OTX](https://otx.alienvault.com) key (OTX also works anonymously). |

### Backend — server & AI

| Variable | Default | Purpose |
|---|---|---|
| `THREATLENS_CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Comma-separated allowed CORS origins for a separately-hosted frontend. |
| `AI_ENABLED` | `false` | Master switch for the AI explanation layer. |
| `AI_PROVIDER` | `ollama` | Which AI provider to use (`ollama` is the only one implemented in v1.0). |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL. |
| `OLLAMA_MODEL` | `qwen3:8b` | Chat model for explanations (never hardcoded). `.env.example` ships the lighter `qwen3:4b` — see [AI Setup](#ai-setup). |
| `AI_TIMEOUT` | `60` | AI request timeout in seconds. |

### Backend — Detection Knowledge Library

| Variable | Default | Purpose |
|---|---|---|
| `THREATLENS_DKL_CACHE_DIR` | *(unset — bundled seed only)* | Optional directory for a synced community-detection cache. Unset means fully offline, seed-only. |
| `THREATLENS_DKL_CACHE_TTL_SECONDS` | `604800` (7 days) | How long a synced cache is considered fresh before `sync_status` reports stale. |

### Backend — Exposure Intelligence (framework-level — reserved, not yet read by any code path)

| Variable | Default | Purpose |
|---|---|---|
| `EXPOSURE_ENABLED` | `false` | Master switch — reserved; no code path reads it yet (each provider self-configures instead, see below). |
| `EXPOSURE_CACHE_ENABLED` | `true` | Reserved — no cache is wired into `ExposureService` itself yet (providers may cache their own lookups, e.g. Shodan). |
| `EXPOSURE_TIMEOUT` | `10` | Reserved per-lookup timeout (seconds). |
| `EXPOSURE_RATE_LIMIT_PER_MINUTE` | *(unset)* | Reserved rate limit. |

### Backend — Exposure Intelligence: Shodan (Phase 5.1)

| Variable | Default | Purpose |
|---|---|---|
| `SHODAN_ENABLED` | `true` | Enables/disables the Shodan provider (`ExposureProviderMetadata.enabled`); `false` excludes it from routing. |
| `SHODAN_API_KEY` | *(unset)* | Free-tier-compatible key from https://account.shodan.io. Unset → every lookup returns a structured `unauthorized` finding, never an error. |
| `SHODAN_TIMEOUT` | `15` | Per-request timeout (seconds). |
| `SHODAN_BASE_URL` | `https://api.shodan.io` | Override for testing or a self-hosted proxy. |

### Backend — Exposure Intelligence: Censys (Phase 5.2)

| Variable | Default | Purpose |
|---|---|---|
| `CENSYS_ENABLED` | `true` | Enables/disables the Censys provider; `false` excludes it from routing. |
| `CENSYS_PERSONAL_ACCESS_TOKEN` | *(unset)* | **Preferred.** From https://search.censys.io/account/api. Sent as `Authorization: Bearer` against the current Platform API; takes precedence over the legacy pair below. |
| `CENSYS_API_ID` | *(unset)* | Legacy — used only when no PAT is set. Paired with `CENSYS_API_SECRET` as HTTP Basic auth against the legacy Search API v2. |
| `CENSYS_API_SECRET` | *(unset)* | Paired with `CENSYS_API_ID`. |
| `CENSYS_TIMEOUT` | `15` | Per-request timeout (seconds). |
| `CENSYS_BASE_URL` | auth-mode-dependent | Override for testing or a self-hosted proxy. Defaults to `https://api.platform.censys.io` with a PAT, `https://search.censys.io/api` with the legacy pair. |

No credentials at all (neither PAT nor the legacy pair) → every lookup returns a structured `unauthorized` finding, never an exception.

### Backend — Exposure Intelligence: GreyNoise (Phase 5.3)

| Variable | Default | Purpose |
|---|---|---|
| `GREYNOISE_ENABLED` | `true` | Enables/disables the GreyNoise provider; `false` excludes it from routing. |
| `GREYNOISE_API_KEY` | *(unset)* | From https://viz.greynoise.io/. Sent as a `key` header. Unset → every lookup returns a structured `unauthorized` finding, never an error. |
| `GREYNOISE_TIMEOUT` | `15` | Per-request timeout (seconds). |
| `GREYNOISE_BASE_URL` | `https://api.greynoise.io` | Override for testing or a self-hosted proxy. |

IPv4 only — GreyNoise's own API scope, not a ThreatLens choice. Reports internet-noise/business-service classification (reputation/context), not scan-surface data; still purely descriptive — GreyNoise's own classification is quoted as a third-party fact, never a ThreatLens-computed verdict.

### Backend — Identity Intelligence (framework-level — reserved, not yet read by any code path)

| Variable | Default | Purpose |
|---|---|---|
| `IDENTITY_ENABLED` | `false` | Master switch — reserved; Phase 6.0 ships zero providers, so no code path reads it yet (each future provider self-configures). |
| `IDENTITY_CACHE_ENABLED` | `true` | Reserved — no cache is wired into `IdentityService` itself yet (a future provider caches its own lookups). |
| `IDENTITY_CACHE_TTL` | `3600` | Reserved cache TTL (seconds). |
| `IDENTITY_TIMEOUT` | `10` | Reserved per-lookup timeout (seconds). |
| `IDENTITY_RATE_LIMIT_PER_MINUTE` | *(unset)* | Reserved rate limit. |

Phase 6.0 is framework only — no providers, no secrets. Provider credentials (Have I Been Pwned, Entra ID, Okta, …) belong to each provider's own settings in a later phase.

### Backend — Investigation Workspace (Phase 8.0)

| Variable | Default | Purpose |
|---|---|---|
| `THREATLENS_WORKSPACE_DIR` | `data/workspace` | Local directory for saved-investigation JSON files (`LocalFileStorage`). Created on first use if missing. |

No authentication, no database — single-user, self-hosted, per the phase brief. See [`docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md`](docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md).

### Frontend

| Variable | Default | Purpose |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `/api/v1` (same-origin) | Base URL of the backend API. |

### Development / testing

| Variable | Purpose |
|---|---|
| `THREATLENS_UPDATE_GOLDEN=1` | Regenerates the golden regression snapshots during `pytest`. Only use for an intentional, reviewed engine change. |

Secrets live in `backend/.env` (git-ignored). Never commit keys.

---

## Health & Monitoring

ThreatLens ships production-grade, **read-only** operational endpoints for liveness/readiness probes, uptime monitoring, and support. Every check is side-effect-free: it never runs an investigation, mutates state, or consumes third-party API quota. The one exception is `GET /health/ai`, which — only when AI is enabled — performs a single lightweight Ollama reachability probe (`/api/tags`), never a model generation.

Each endpoint is mounted at the **root** (for infrastructure probes hitting the backend directly) and under **`/api/v1`** (so a same-origin frontend can reach it through the existing API base):

| Endpoint | Purpose | Status |
|---|---|---|
| `GET /health` | Liveness — the process is up (service, version, uptime). | `200` |
| `GET /ready` | Readiness — the deterministic core (detection · reasoning · bundled knowledge) can serve. | `200` ready · `503` not ready |
| `GET /health/providers` | Threat-intelligence provider configuration (enabled · requires-auth · configured). No network. | `200` |
| `GET /health/knowledge` | Reference-knowledge dataset status and versions. Offline; no network. | `200` |
| `GET /health/ai` | AI subsystem status (disabled · reachable · unavailable). The only endpoint that may touch the network. | `200` |
| `GET /version` | Component versions: platform, API, the frozen reasoning engine, and build commit/timestamp. | `200` |

Readiness deliberately ignores TI credentials and the AI layer — both are **optional enrichment** whose absence must never take the service out of rotation. A missing TI key surfaces as `degraded` on `/health/providers` (informational), not as a failed readiness check.

```bash
curl -s localhost:8000/health     | jq   # liveness
curl -s localhost:8000/ready      | jq   # readiness (503 if the core is down)
curl -s localhost:8000/version    | jq
curl -s localhost:8000/health/ai  | jq   # "disabled" by default
```

Sample `GET /health`:

```json
{ "status": "ok", "service": "threatlens", "version": "1.0.0",
  "uptime_seconds": 12.4, "started_at": "…", "timestamp": "…" }
```

Kubernetes / Docker probes map directly onto the two probes:

```yaml
livenessProbe:  { httpGet: { path: /health, port: 8000 } }
readinessProbe: { httpGet: { path: /ready,  port: 8000 } }
```

Build provenance on `/version` (`build.commit` / `build.timestamp`) is read from environment variables when set (`THREATLENS_BUILD_COMMIT` / `VERCEL_GIT_COMMIT_SHA` / `GIT_COMMIT`, and `THREATLENS_BUILD_TIME` / `BUILD_TIMESTAMP`); otherwise `null`. The frontend shows a passive status pill (top-right) driven by `GET /health` and `GET /health/ai` — click it to open the **Operational Dashboard**.

### Operational Dashboard

A read-only page for administrators/developers at **`/dashboard`** (separate from the Investigation Workspace), covering three tabs backed by three endpoints under `/api/v1/system`:

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/system/health` | Per-service Healthy/Degraded/Offline/Disabled (backend, API, TI providers, knowledge providers, AI, Detection Engine, Detection Knowledge Library) plus an overall rollup. Reuses the checks above — no new probing. |
| `GET /api/v1/system/usage` | Incremental request/success/failure/latency counters per TI and knowledge provider, the AI layer, Detection Engineering generations, Detection Knowledge queries, and investigation statistics (avg duration/findings/recommendations/confidence). In-memory, process-local, reset on restart — no database, no monitoring stack. |
| `GET /api/v1/system/config` | Configured/enabled booleans per provider and the AI provider/model. Never a key, token, secret, or credential-bearing URL. |

The dashboard is strictly downstream and isolated: it never calls a provider, runs an investigation, generates a detection, or invokes the AI layer — it only reads already-computed response objects and existing configuration checks. See [`docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md`](docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md) for the full design.

### Exposure Intelligence — frozen at v1.0 (Phase 5.0-5.4)

`GET /api/v1/exposure` reports framework + per-provider status — `{status, message, framework_version, providers_registered, providers[], summary}` — and, given an optional `?value=` query param (an IP), also runs a real lookup and returns the merged `summary` (an `ExposureSummary`: findings, evidence, assets, references) across every enabled provider. The **`/exposure`** page shows Provider Status (framework version, provider count, each provider's health) plus a search box; results render per-provider with full evidence/asset detail when configured, or a friendly message when a provider is disabled or missing credentials — never a crash. Three providers (Censys, GreyNoise, Shodan) merge into one summary through the same unmodified aggregation path Phase 5.0 shipped with zero providers. GreyNoise contributes reputation/context (internet-noise/business-service classification, IPv4 only) rather than scan-surface data, still reported purely descriptively. Phase 5.4 validated the whole framework against a 153-scenario corpus (zero invariant violations, byte-stable golden snapshot, benchmarked scaling/caching) and froze it at `EXPOSURE_FRAMEWORK_VERSION = "1.0"`. Still not integrated into `/investigate`. See [`docs/architecture/PHASE-5.0-EXPOSURE-FRAMEWORK.md`](docs/architecture/PHASE-5.0-EXPOSURE-FRAMEWORK.md), [`docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md`](docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md), [`docs/architecture/PHASE-5.2-CENSYS-PROVIDER.md`](docs/architecture/PHASE-5.2-CENSYS-PROVIDER.md), [`docs/architecture/PHASE-5.3-GREYNOISE-PROVIDER.md`](docs/architecture/PHASE-5.3-GREYNOISE-PROVIDER.md), and [`docs/architecture/PHASE-5.4-EXPOSURE-ENGINE-V1.md`](docs/architecture/PHASE-5.4-EXPOSURE-ENGINE-V1.md).

### Identity Intelligence (Phase 6.0 — framework only)

`GET /api/v1/identity` reports framework readiness — `{status, message, framework_version, providers_registered}` — a pure status probe that performs no entity lookup and never touches the network. The **`/identity`** page shows Framework Ready, provider count, and architecture version. Identity Intelligence is a fourth, separate framework answering "what is known about this identity" (breaches, credential exposure, paste history, linked accounts, directory profile, group membership, MFA state, sign-in activity, first-party risk signals) — never "is it malicious" or "where is it exposed" (Threat and Exposure Intelligence's questions). Purely descriptive: a provider's own risk signal is quoted as a third-party fact, never a ThreatLens verdict. Phase 6.0 ships the framework — models, provider interface, registry, config, cache, service — with **zero** providers, exactly as Exposure's Phase 5.0 did; every code path is real and tested against an empty registry. Provider integrations (Have I Been Pwned, Entra ID, Okta, …) arrive in a later phase. See [`docs/architecture/PHASE-6.0-IDENTITY-FRAMEWORK.md`](docs/architecture/PHASE-6.0-IDENTITY-FRAMEWORK.md).

### Investigation Correlation Engine (Phase 7.0-7.1 — engine + rule library, not yet integrated)

`GET /api/v1/correlation` reports engine readiness — `{status, message, framework_version, rules_registered}` — a pure status probe that runs no correlation and never touches the network. The **`/correlation`** page shows Engine Ready, registered-rule count, and architecture version. The Correlation Engine is a pure, deterministic consumer of a completed `InvestigationSummary`: it combines the investigation's **existing** findings into higher-level *observations* (e.g. "malicious infrastructure with exposed services", "known malware associated with an observed ATT&CK technique"), each referencing the source findings it combines. It never invents evidence, never scores, and never produces confidence/severity/priority — those remain the Reasoning Engine's job. No AI, no ML, no probabilistic inference: **70 declarative rules** (`backend/src/threatlens/correlation/rules/` — one module per domain: infrastructure, vulnerability, malware, threat actor, campaign, MITRE technique, and three-signal compound escalations) interpreted by one generic evaluator, with content-addressed, timestamp-independent identity. Phase 7.0 shipped the engine + a 12-rule seed set; Phase 7.1 expanded the library to 70 rules with zero engine/registry/model-structure/API changes. Still not integrated into `/investigate`. See [`docs/architecture/PHASE-7.0-CORRELATION-FRAMEWORK.md`](docs/architecture/PHASE-7.0-CORRELATION-FRAMEWORK.md) and [`docs/architecture/PHASE-7.1-CORRELATION-RULE-LIBRARY.md`](docs/architecture/PHASE-7.1-CORRELATION-RULE-LIBRARY.md).

### Investigation Workspace — persistence + timeline + graph (Phase 8.0-8.2)

`POST/GET/PUT/DELETE /api/v1/workspace[/{id}]` save, load, update, delete, and list completed investigations — a workflow and persistence layer over the pipeline above, **not a new intelligence engine**. A saved record's metadata (title, status, tags, analyst summary, severity, investigation type) is entirely new; its `investigation_summary`/`detection_package`/`correlation_summary` fields are the existing engines' own output models, attached verbatim and never recomputed. Local JSON file storage (`THREATLENS_WORKSPACE_DIR`, default `data/workspace`), no auth, single-user. The **`/workspace`** page lists saved investigations with search and status/severity filters; **`/workspace/{id}`** shows one full record, reusing the existing `InvestigationSummaryCard`/`RecommendationRollup`/`FindingsSection` components. A **Save to Workspace** button on the per-search Investigation Workspace UI (see Features, above — the two "Investigation Workspace" names are disambiguated in the architecture doc) persists the investigation just run. See [`docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md`](docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md).

**Phase 8.1** adds `GET /api/v1/workspace/{id}/timeline` — a read-only, derived view that reconstructs chronological events **only** from evidence that already carries an explicit, timezone-aware timestamp (`Evidence.observed_at`); missing or timezone-naive timestamps are silently omitted, never invented or estimated. Duplicate evidence cited by more than one finding collapses into one content-addressed, deterministically-ordered event. Detection and Correlation outputs contribute no events (neither carries a per-item timestamp, only a processing-time `generated_at`). The detail page's collapsed "Timeline" section fetches this lazily on first expand. See [`docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md`](docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md).

**Phase 8.2** adds `GET /api/v1/workspace/{id}/graph` — a read-only, derived Evidence Relationship Graph: nodes are a finding's own subject entity, a relationship's target entity, or a correlation observation; edges are a finding's explicit `Relationship`, a correlation observation's hub edge to each entity it cites, or a correlation rule's own typed relationship between two entities — never an entity or relationship invented, never a connection drawn merely from co-occurrence. Content-addressed node/edge ids; same-subject correlation relationships are represented via the observation's hub edges rather than a self-loop. Timeline and Graph are sibling derived views — neither depends on the other. The detail page's collapsed "Evidence Graph" section fetches this lazily on first expand. See [`docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md`](docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md).

---

## AI Setup

ThreatLens supports **local AI through Ollama**. AI is **optional** — the platform works perfectly without it. The AI layer only generates *explanations* of a completed investigation; the deterministic reasoning engine remains the single source of truth.

> **AI never changes findings.** It cannot alter findings, evidence, confidence, severity, priority, or recommendations — structurally (the output model has no such fields) and operationally (grounding drops fabricated references). It only explains the `InvestigationSummary`.

### Enable AI in under five minutes

1. **Install Ollama** — https://ollama.com (macOS / Linux / Windows).
2. **Pull the recommended model:**
   ```bash
   ollama pull qwen3:4b
   ```
3. **Verify Ollama is running:**
   ```bash
   curl http://localhost:11434/api/tags
   ```
   You should get JSON listing your local models (including `qwen3:4b`).
4. **Configure `.env`** (copy the example first if needed):
   ```bash
   cp backend/.env.example backend/.env
   # then set, in backend/.env:
   AI_ENABLED=true
   AI_PROVIDER=ollama
   OLLAMA_URL=http://localhost:11434
   OLLAMA_MODEL=qwen3:4b
   AI_TIMEOUT=60
   ```
5. **Restart the backend** (settings are read at startup):
   ```bash
   uvicorn threatlens.api.app:app --reload
   ```
6. **Open the Investigation Workspace**, run any investigation, and expand the **AI Explanation** card.

With AI disabled (the default) or Ollama not running, the card simply shows "AI explanation unavailable." and the deterministic investigation renders normally.

### Recommended models (hardware)

Larger models improve the *writing quality* of explanations but **do not affect deterministic findings, confidence, priority, or recommendations** — those come only from the reasoning engine.

| Hardware | Recommended model | Notes |
|---|---|---|
| Laptop (8 GB RAM) | `qwen3:4b` *(recommended default)* | Ships in `.env.example`; fast, low memory. |
| Laptop / Desktop (16 GB RAM) | `qwen3:8b` | The engine's built-in default when `OLLAMA_MODEL` is unset. |
| Mini PC / Desktop (32 GB+ RAM) | `qwen3:14b` (and larger future models) | Best writing quality. |

Set your choice via `OLLAMA_MODEL` — it is never hardcoded. Any Ollama chat model works; the `qwen3:*` family is recommended.

### Grounding & safety

- The `PromptBuilder` serializes **only** the deterministic `InvestigationSummary` — never raw provider responses, WHOIS, or vendor JSON — wraps it in explicit *untrusted data* delimiters, and tells the model to ignore embedded instructions, invent nothing, and modify nothing.
- **Grounding is enforced in code:** any AI statement referencing a finding ID or recommendation absent from the summary is dropped before it reaches the API.
- **Failure is graceful:** AI disabled → `disabled`; Ollama offline → `unavailable`; malformed output → `error`. The investigation always succeeds; the endpoint never throws.
- **Future providers:** OpenAI, Anthropic, Gemini, and Azure OpenAI slot in behind the same `AIProvider` interface with zero caller changes (`AI_PROVIDER=openai`, …) — not implemented in v1.0.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "AI explanation unavailable." in the UI | AI disabled, or Ollama unreachable | Confirm `AI_ENABLED=true` in `backend/.env` and that Ollama is running (`curl http://localhost:11434/api/tags`). |
| `connection refused` / `unavailable` | Ollama not running | Start it — `ollama serve` (or launch the Ollama app) — then retry the curl check. |
| `model "qwen3:4b" not found` | Model not pulled | `ollama pull qwen3:4b` (or whatever `OLLAMA_MODEL` is set to); confirm with `ollama list`. |
| Explanation never appears, then `unavailable` | Request timed out (large model / slow host) | Raise `AI_TIMEOUT` (e.g. `120`) or switch to a smaller model (`qwen3:4b`). |
| Incorrect `OLLAMA_URL` | URL points at the wrong host/port | Match your Ollama server; default `http://localhost:11434`. From inside Docker, use the host address, not `localhost`. |
| `out of memory`, host swapping, or model killed | Model too large for available RAM | Pick a smaller model per the table above; check loaded models with `ollama ps`. |
| Backend ignores new settings | `.env` not reloaded | Restart the backend after editing `.env`. |

Diagnostic commands:

```bash
ollama list                              # models available locally
ollama ps                                # models currently loaded (memory use)
curl http://localhost:11434/api/tags     # is the Ollama server reachable?
```

---

## Testing

| Suite | Size | What it locks down |
|---|---|---|
| Backend tests | **2,668 passing, 1 skipped** | Detection, providers, aggregation, reasoning, AI layer, detection engineering, Sigma + YARA + Suricata + Snort + SIEM generation, the community Detection Knowledge Library, correlation, exposure, identity, the Investigation Workspace + Timeline + Evidence Graph, API contracts, health/readiness. |
| Frontend tests | 132 passing (Vitest) | API client behaviour incl. `explain()`, `generateDetections()`, `recommendCommunityDetections()`, the Investigation Workspace client (`saveInvestigation`/`listInvestigations`/`getInvestigation`/`updateInvestigation`/`deleteInvestigation`/`getInvestigationTimeline`/`getInvestigationGraph`), detection + knowledge helpers, health checks, and abort handling. |
| 100-IOC validation suite | 318 tests | The complete pipeline over ~100 curated real-world IOC investigations (`backend/tests/validation/`). |
| Reasoning benchmark | 179 tests / 58 scenarios | The frozen Reasoning Engine v1.0 contract (`backend/tests/benchmark/`). |
| Detection freeze suite | 184 tests / 140-scenario corpus | The frozen **Detection Engine v1.0** contract — every scenario × nine generators, invariants, validators, and golden regression (`backend/tests/detection/`). |
| Detection Knowledge Library | 74 tests | Community normalization, search, similarity, matching, licensing, versioning, offline cache, and golden regression (`backend/tests/detection_library/`). |
| Investigation Workspace suite | 95 tests | Models, local-file storage, service (CRUD + filtering), API contract, and a dedicated no-regression suite proving every pre-Phase-8.0 route/engine-version/CORS behavior is unchanged (`backend/tests/workspace/`). |
| Investigation Timeline suite | 81 tests / 10-scenario golden corpus | Timestamp policy (missing/naive/valid), deduplication, content-addressed identity, deterministic ordering, API contract, and a no-regression suite (`backend/tests/timeline/`). |
| Evidence Relationship Graph suite | 91 tests / 15-scenario golden corpus | Canonicalization (vocabulary alignment), deduplication, content-addressed node/edge identity, same-subject self-loop omission, deterministic ordering, API contract, and a no-regression suite (`backend/tests/graph/`). |
| Golden regression | pinned snapshots | Byte-level snapshots of reasoning summaries, all nine generators' output, **and** community normalization + matching; any drift fails CI and requires an explicit `THREATLENS_UPDATE_GOLDEN=1` regeneration plus review. |

```bash
cd backend && pytest                            # full backend suite (offline)
cd backend && python tests/benchmark/perf.py    # reasoning performance report
cd backend && python tests/detection/perf.py    # detection generation scaling report
cd backend && python tests/detection_library/perf.py  # community library scaling report
cd frontend && npm test && npm run build
```

Everything runs offline: external TI providers are exercised against recorded/simulated payloads and Ollama is mocked — CI needs no network, no API keys, and no local model.

---

## Roadmap

| Phase | Capability |
|---|---|
| **Phase 4 — Detection Engineering** ✅ | Generate detections (Sigma/YARA/SIEM queries) from investigation findings; deterministic templating with validated output, citing the findings each rule derives from. Frozen at v1.0, plus a read-only **Detection Knowledge Library** recommending community detections alongside generated ones. |
| **Phase 5 — Exposure Intelligence** ✅ **v1.0 frozen** | Asset/exposure context: what is internet-facing, what is vulnerable, how findings map to your attack surface. Answers "where is this exposed", never "is this malicious" — a separate framework from Threat Intelligence. **Phase 5.0 (framework)**, **Phase 5.1 (Shodan)**, **Phase 5.2 (Censys)**, **Phase 5.3 (GreyNoise)**, and **Phase 5.4 (validation & freeze)** are complete — three independent providers merge into one summary with zero framework changes, validated against a 153-scenario corpus with zero invariant violations and frozen at `EXPOSURE_FRAMEWORK_VERSION = "1.0"`. See [`docs/architecture/PHASE-5.0-EXPOSURE-FRAMEWORK.md`](docs/architecture/PHASE-5.0-EXPOSURE-FRAMEWORK.md), [`docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md`](docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md), [`docs/architecture/PHASE-5.2-CENSYS-PROVIDER.md`](docs/architecture/PHASE-5.2-CENSYS-PROVIDER.md), [`docs/architecture/PHASE-5.3-GREYNOISE-PROVIDER.md`](docs/architecture/PHASE-5.3-GREYNOISE-PROVIDER.md), and [`docs/architecture/PHASE-5.4-EXPOSURE-ENGINE-V1.md`](docs/architecture/PHASE-5.4-EXPOSURE-ENGINE-V1.md). Further providers (HIBP, SecurityTrails, …), domain/email exposure, and `InvestigationSummary` integration are later, unstarted milestones. |
| **Phase 6 — Identity Intelligence** 🚧 | Identity-centric investigation: accounts, credentials, breaches, directory profiles, and identity-driven attack paths. Answers "what is known about this identity", never "is this malicious" or "where is this exposed" — a fourth separate framework. **Phase 6.0 (framework)** is complete — models, provider interface, registry, config, cache, service, `GET /api/v1/identity`, and a `/identity` placeholder, with **zero** providers, exactly as Exposure's Phase 5.0 shipped. See [`docs/architecture/PHASE-6.0-IDENTITY-FRAMEWORK.md`](docs/architecture/PHASE-6.0-IDENTITY-FRAMEWORK.md). Concrete providers (Have I Been Pwned, Entra ID, Okta, …) and any `InvestigationSummary` integration are later, unstarted milestones. |
| **Phase 7 — Investigation Correlation Engine** 🚧 | Deterministically combines a completed investigation's existing findings into higher-level correlation observations (e.g. "malicious infrastructure with exposed services") before higher-level reasoning consumes them. Only combines evidence, never invents it — no AI, no ML, no scoring. **Phase 7.0 (framework)** shipped canonical models, a declarative rule model, a single generic evaluator, registry, service, `GET /api/v1/correlation`, and a `/correlation` placeholder, with content-addressed timestamp-independent identity and a CI-gated golden snapshot. **Phase 7.1 (rule library)** expanded the seed set from 12 to **70 rules** across 7 domain modules, with zero engine/registry/model-structure/API changes. See [`docs/architecture/PHASE-7.0-CORRELATION-FRAMEWORK.md`](docs/architecture/PHASE-7.0-CORRELATION-FRAMEWORK.md) and [`docs/architecture/PHASE-7.1-CORRELATION-RULE-LIBRARY.md`](docs/architecture/PHASE-7.1-CORRELATION-RULE-LIBRARY.md). `/investigate` integration, Case Management, and SOAR are later, unstarted milestones. |
| **Phase 8 — Investigation Workspace** ✅ | A workflow and persistence layer over the completed analytical pipeline — **not a new intelligence engine.** **Phase 8.0** ships save/load/update/delete/list/filter/search over completed investigations (`/api/v1/workspace`, a `/workspace` list + detail UI, and a **Save to Workspace** button on the per-search analyst UI), backed by local file storage behind a swappable `WorkspaceStorage` interface — no auth, no database, single-user, per the phase brief. Consumes the existing `InvestigationSummary`/`DetectionPackage` (and, once a later phase wires Correlation into `/investigate`, `CorrelationSummary`) verbatim; generates nothing. **Phase 8.1** adds a read-only, derived **Investigation Timeline** (`GET /api/v1/workspace/{id}/timeline`): chronological events reconstructed only from evidence that already carries an explicit, timezone-aware timestamp — never invented, estimated, or causally linked. Content-addressed event ids; duplicate evidence cited by more than one finding collapses into one canonical event. **Phase 8.2** adds a read-only, derived **Evidence Relationship Graph** (`GET /api/v1/workspace/{id}/graph`): nodes and edges reconstructed only from a finding's explicit `Relationship`s and a correlation observation's cited findings/relationships — never an invented entity, relationship, or a connection drawn merely from co-occurrence. Content-addressed node/edge ids; a sibling of Timeline, not a consumer of it. See [`docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md`](docs/architecture/PHASE-8.0-INVESTIGATION-WORKSPACE.md) (including the disambiguation from the existing, unrelated "Investigation Workspace" analyst UI), [`docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md`](docs/architecture/PHASE-8.1-INVESTIGATION-TIMELINE.md), and [`docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md`](docs/architecture/PHASE-8.2-EVIDENCE-RELATIONSHIP-GRAPH.md). Analyst Notes, Audit History, Case Management, RBAC, STIX/TAXII, SOAR, and other enterprise features are later, unstarted milestones. |

All future phases consume the frozen `InvestigationSummary` — the reasoning core does not change to support them. Exposure Intelligence (Phase 5) and Identity Intelligence (Phase 6) are additionally isolated from Threat Intelligence, Knowledge Intelligence, Reasoning, Detection Engineering, the Detection Knowledge Library, and the Operational Dashboard — no shared models, no shared registry, dependency flows one way into `entities/` only. The Investigation Correlation Engine (Phase 7) is a pure, read-only consumer of the `InvestigationSummary` (like the Detection Engine) — it never mutates it and never invents evidence. The Investigation Workspace (Phase 8) is a persistence layer, not an analytical consumer — it stores whatever the engines above already produced and never computes anything itself.

---

## Versioning

ThreatLens follows [Semantic Versioning](https://semver.org/). **v1.0.0** was the first stable Core Platform release; **v1.1.0** adds Detection Engineering (nine generators + the Detection Knowledge Library) additively — new analyst-facing capability, new endpoints, no change to any frozen engine's output contract. **v1.1.1** is a patch: the read-only **Operational Dashboard** (admin/developer-only observability, not an investigation capability) plus frontend presentation refinements (Detection Workspace v1, Investigation Workspace v2, Tag Presentation v1) — no new analyst-facing capability, no engine change. **v1.2.0** adds Exposure Intelligence's concrete providers (Shodan, Censys, GreyNoise) and freezes it at `EXPOSURE_FRAMEWORK_VERSION = "1.0"` (Phases 5.1–5.4), plus two new framework-only subsystems with zero concrete providers/rules exercised yet — Identity Intelligence (Phase 6.0) and the Investigation Correlation Engine (Phase 7.0) — additively, with no change to any frozen engine's output contract. Patch releases (v1.x.y) fix bugs or add non-capability tooling/presentation without changing engine output or analyst-facing behavior; minor releases add analyst-facing capability additively — new providers, new investigation/detection consumers; a major release (v2.0.0) is required for any breaking change to the public API or an engine's output contract.

The **package/release version** (this badge, `pyproject.toml`, `package.json`, the git tag) advances with every release. It is deliberately separate from the **frozen engine version constants** (`ENGINE_VERSION` for reasoning, `DETECTION_ENGINE_VERSION` for detection — both still `"1.0"`) and from the **running platform version** reported by `GET /version` (`threatlens.__version__`, still `"1.0.0"`): the latter is embedded verbatim in generated YARA/Chronicle rule content, so it is part of the frozen Detection Engine v1.0 golden output and only changes alongside a deliberate, reviewed golden regeneration — never as a side effect of an ordinary release.

## License

[MIT](LICENSE)
