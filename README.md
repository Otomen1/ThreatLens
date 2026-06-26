# ThreatLens

A search-first threat-intelligence platform. Search **any** indicator — IP,
domain, URL, file hash, CVE, MITRE technique, malware family, threat actor — and
ThreatLens identifies the entity type deterministically, routes it to the
intelligence providers that can enrich it, and returns one aggregated,
evidence-first result. No AI is used for detection or verdicts; the engine is
deterministic and reproducible.

> Status: Phase 1.6. Universal entity detection + provider framework +
> aggregation, with three live providers (MalwareBazaar, URLhaus, AbuseIPDB).
> AI synthesis, scoring, persistence, and report parsing are future phases.

## Architecture

```
query ─▶ Entity Detection (deterministic) ─▶ Provider Router ─▶ providers (async, concurrent)
                                                                      │
                                              Aggregation Engine ◀────┘
                                                      │
                                              IntelligenceResponse ─▶ frontend
```

- **Entity Detection** (`backend/src/threatlens/search`) — priority-ordered,
  validated detectors classify raw input into a normalized `Entity`. No regex
  guessing for soft types; reference data backs them.
- **Provider Framework** (`backend/src/threatlens/providers`) — each provider
  declares `ProviderMetadata` (supported types, capabilities, auth) and returns
  the canonical `IntelligenceResult`. A registry + router map entity types to
  capable providers. Raw vendor JSON never leaves a provider.
- **Aggregation Engine** (`providers/aggregation.py`) — merges per-provider
  results into one `AggregatedResult`: provider attribution, de-duplicated
  evidence/relationships/references, namespaced metadata. No scoring; failures
  are values, so one provider failing never fails the search.
- **API** (`backend/src/threatlens/api`) — FastAPI. `POST /api/v1/detect`
  (detection only) and `POST /api/v1/intelligence` (detect + enrich + aggregate).
- **Frontend** (`frontend`) — Next.js; a provider-agnostic panel renders the
  aggregated result.

## Repository layout

```
backend/   FastAPI app + detection engine + providers (Python 3.11+)
frontend/  Next.js app (TypeScript) — deployed on Vercel
docs/      Architecture documentation
```

## Local development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # then fill in API keys (see below)
uvicorn threatlens.api.app:app --reload
```

Quality gates:

```bash
ruff check src tests      # lint
mypy src/threatlens       # types (strict)
pytest                    # tests
```

### Frontend

```bash
cd frontend
npm install
npm run dev                          # http://localhost:3000
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 npm run dev   # point at local backend
npm test                             # vitest
```

## Configuration

Secrets are read from environment variables only (never committed). Locally,
`backend/.env` is loaded automatically; in production set them in the host's
environment (e.g. Vercel project settings).

| Variable | Purpose |
|---|---|
| `ABUSE_CH_AUTH_KEY` | abuse.ch Auth-Key — powers **MalwareBazaar** and **URLhaus** (one free key for all abuse.ch services, from https://auth.abuse.ch). |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key for IP reputation (https://www.abuseipdb.com). |
| `NEXT_PUBLIC_API_URL` | Frontend → backend base URL. Defaults to same-origin `/api/v1`. |
| `THREATLENS_CORS_ORIGINS` | Comma-separated allowed origins for a separately-hosted frontend. |

Missing keys degrade gracefully — affected providers return a structured
`unauthorized` result rather than crashing the search.

## Deployment

The frontend is deployed on Vercel; the FastAPI app runs as a Vercel Python
function (`frontend/api/index.py`) with the engine vendored in at build time
(`frontend/scripts/vendor-engine.mjs`). Set the API keys above in the Vercel
project's environment variables.

## CI

`.github/workflows/ci.yml` runs backend lint/type/tests and the frontend
build/tests on every push and pull request.
