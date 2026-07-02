# ThreatLens

**A search-first, deterministic threat-intelligence and investigation platform.**

[![CI](https://github.com/Otomen1/ThreatLens/actions/workflows/ci.yml/badge.svg)](https://github.com/Otomen1/ThreatLens/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
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
| **Investigation Workspace** | A Next.js analyst UI: assessment headline, priority-ordered recommendations, expandable finding cards with confidence breakdowns, provider details, relationships, and references. |
| **Provider Framework** | Plug-in architecture for both TI and knowledge providers — declare metadata, return the canonical `IntelligenceResult`, register in one place. |
| **Offline Operation** | Detection, knowledge lookup, reasoning, and the full test suite run with zero network access. External TI and AI are optional add-ons. |
| **Deterministic Reasoning** | No AI, no randomness, no wall-clock dependence in the core. Regression-locked by golden snapshots (155 pinned investigations across two suites). |

---

## Screenshots

> Screenshots live in `docs/screenshots/`. Placeholders below — capture from a local run (`uvicorn threatlens.api.app:app` + `npm run dev`).

| View | Screenshot |
|---|---|
| Dashboard (search) | `docs/screenshots/dashboard.png` *(placeholder)* |
| Investigation Workspace | `docs/screenshots/investigation-workspace.png` *(placeholder)* |
| Findings | `docs/screenshots/findings.png` *(placeholder)* |
| Recommendations | `docs/screenshots/recommendations.png` *(placeholder)* |
| AI Explanation | `docs/screenshots/ai-explanation.png` *(placeholder)* |

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
ollama pull qwen3:8b
export AI_ENABLED=true          # AI is OFF by default
uvicorn threatlens.api.app:app
```

ThreatLens functions identically without Ollama — the AI card simply reports "AI explanation unavailable."

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
| `OLLAMA_MODEL` | `qwen3:8b` | Chat model used for explanations (never hardcoded). |
| `AI_TIMEOUT` | `60` | AI request timeout in seconds. |

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

## AI

ThreatLens treats AI as a **downstream consumer, never a decision-maker**:

- **Ollama (v1.0):** local, private LLM inference. The `PromptBuilder` serializes only the deterministic `InvestigationSummary` — no raw provider responses, no WHOIS, no vendor JSON — wraps it in explicit *untrusted data* delimiters, and instructs the model to ignore embedded instructions, invent nothing, and modify nothing.
- **Grounding is enforced in code, not just prompted:** any AI statement referencing a finding ID or recommendation that does not exist in the summary is dropped before it reaches the API.
- **Failure is graceful:** AI disabled → structured `disabled` response; Ollama offline → structured `unavailable`; malformed output → structured `error`. The investigation always succeeds; the endpoint never throws.
- **Future providers:** OpenAI, Anthropic, Gemini, and Azure OpenAI slot in behind the same `AIProvider` interface with zero caller changes (`AI_PROVIDER=openai` etc. — not implemented in v1.0).

> **AI never changes findings.** It cannot alter findings, evidence, confidence, severity, priority, or recommendations — structurally (the output model has no such fields) and operationally (grounding drops fabricated references).

---

## Testing

| Suite | Size | What it locks down |
|---|---|---|
| Backend tests | **1,177 passing** | Detection, providers, aggregation, reasoning, AI layer, API contracts. |
| Frontend tests | 9 passing (Vitest) | API client behaviour incl. `explain()` and abort handling. |
| 100-IOC validation suite | 316 tests | The complete pipeline over ~100 curated real-world IOC investigations (`backend/tests/validation/`). |
| Reasoning benchmark | 179 tests / 58 scenarios | The frozen Reasoning Engine v1.0 contract (`backend/tests/benchmark/`). |
| Golden regression | 155 pinned summaries | Byte-level snapshots of engine output (58 benchmark + 97 validation); any drift fails CI and requires an explicit `THREATLENS_UPDATE_GOLDEN=1` regeneration plus review. |

```bash
cd backend && pytest                            # full backend suite (offline)
cd backend && python tests/benchmark/perf.py    # performance report
cd frontend && npm test && npm run build
```

Everything runs offline: external TI providers are exercised against recorded/simulated payloads and Ollama is mocked — CI needs no network, no API keys, and no local model.

---

## Roadmap

| Phase | Capability |
|---|---|
| **Phase 4 — Detection Engineering** | Generate detections (Sigma/YARA/SIEM queries) from investigation findings; deterministic templating with validated output, citing the findings each rule derives from. |
| **Phase 5 — Exposure Intelligence** | Asset/exposure context: what is internet-facing, what is vulnerable, how findings map to your attack surface. |
| **Phase 6 — Identity Intelligence** | Identity-centric investigation: accounts, credentials, and identity-driven attack paths. |

All future phases consume the frozen `InvestigationSummary` — the reasoning core does not change to support them.

---

## Versioning

ThreatLens follows [Semantic Versioning](https://semver.org/). **v1.0.0** is the first stable Core Platform release. Patch releases (v1.0.x) fix bugs without changing engine output; minor releases (v1.1.0, …) add capabilities additively — new providers, new consumers, new endpoints; a major release (v2.0.0) is required for any breaking change to the public API or the reasoning output contract. Engine-output changes are always deliberate: they require regenerating the golden snapshots and bumping `ENGINE_VERSION`.

## License

[MIT](LICENSE)
