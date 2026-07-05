# Phase 5.2 — Censys Exposure Provider

## Status

Complete. The second concrete Exposure Intelligence provider — and the
framework-validation milestone: proving the Phase 5.0 framework and Phase
5.1's per-provider pattern both scale to multiple providers with **no
architectural change**. Every other subsystem remains frozen and untouched.

## Purpose

Adds [Censys](https://search.censys.io) as a second, independent source of
"where is this IP exposed" (open ports, services, TLS certificates,
reverse-DNS hostnames, hosting/ASN) alongside Shodan. Still purely
descriptive — no score, no reputation, no verdict.

## Framework validation summary

This phase's explicit goal was to confirm that registering a second provider
requires **no redesign**. It didn't:

| Layer | Change required | What actually happened |
|---|---|---|
| `exposure/registry.py` | Add one provider to `build_default_registry()` | One `registry.register(CensysProvider())` line, exactly as Phase 5.1's own doc predicted this integration point |
| `exposure/service.py` | None | Completely unmodified — `ExposureService.investigate()` already fanned out to *every* routed provider via `asyncio.gather` and merged via `merge_findings()`; two providers exercise the same code path one already did |
| `exposure/summary.py` | None | `merge_findings()` already aggregated an arbitrary number of findings |
| Provider ordering | None | Both providers default to `priority=100`; the existing priority-then-name tiebreak (already tested in Phase 5.0) makes `censys` sort before `shodan` deterministically, with no new ordering logic |
| `api/app.py` (`GET /api/v1/exposure`) | None | The endpoint already gathered `p.health()` over `_exposure_registry.providers` (plural) and called `_exposure_service.investigate()` once; a second provider just means the existing loops and the existing merge produce two entries instead of one |
| `frontend/app/exposure/page.tsx`, `ExposureFindingCard.tsx` | None | Both already iterate generically over `state.status.providers` and `summary.findings` — verified by mocking a two-provider API response and confirming Censys renders correctly with zero frontend code changes (browser-verified, screenshot in the deliverables) |

The only genuinely new code is `CensysProvider` itself (`lookup`/
`normalize`/`health`/`configuration`) — a leaf, not a framework change.

## Architecture decisions

- **HTTP Basic Auth (API ID + Secret) instead of a single key.** Censys's
  API uses a credential pair, unlike Shodan's single key. This is handled
  entirely inside `CensysProvider` (a private `_auth_header()` building a
  `Basic` header) — no framework change, since `ExposureProviderMetadata`
  already models `auth_type` generically and the shared `HttpClient.get()`
  already accepts arbitrary headers.
- **Same IPv4/IPv6-only scope decision as `ShodanProvider`, for the same
  reason.** Censys's host view (`/v2/hosts/{ip}`) is IP-keyed; domain
  exposure would need a separate resolution step the API doesn't offer as
  one unambiguous call. Deferred, not guessed at.
- **Reuses `providers/http.py`'s `HttpClient`** — the same disclosed,
  narrow exception to Phase 5.0's isolation rule that `ShodanProvider`
  already established (see `docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md`).
  No file under `providers/` is modified.
- **Provider-local cache, mirroring `ShodanProvider` exactly** — an
  `InMemoryExposureCache` scoped to `CensysProvider`, one-hour TTL, only
  `OK`/`NOT_FOUND` cached. No change to the framework's cache abstraction.
- **Same category-selection heuristic**: `OPEN_PORTS` if `services` is
  non-empty, else `HOSTING` if hosting/location data exists, else `None` —
  applied to Censys's own field names, proving the heuristic isn't
  Shodan-specific.
- **Test-isolation fix (`tests/exposure/conftest.py`, new):** once a real
  `SHODAN_API_KEY` exists in a developer's `backend/.env` (as it now does,
  for actual use), `api/app.py`'s `load_dotenv()` leaks it into `os.environ`
  the moment any test imports the app, silently changing what
  "credentials not configured" tests exercise. An autouse fixture clears
  the provider-credential env vars before every test in this package —
  mirroring the existing precedent in `tests/system/conftest.py` — so the
  suite's outcome never depends on what happens to be in a local `.env`.
  Two `test_api.py` tests that exercise the process-wide app singleton
  (whose providers are constructed once, at import time, from whatever the
  environment was then) additionally inject an explicitly-unconfigured
  registry, the same technique the file already used for its
  disabled-registry test.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CENSYS_ENABLED` | `true` | Maps to `ExposureProviderMetadata.enabled`; `false` excludes Censys from routing. |
| `CENSYS_API_ID` | unset | From https://search.censys.io/account/api. |
| `CENSYS_API_SECRET` | unset | Paired with `CENSYS_API_ID`. Either missing → every lookup returns a structured `unauthorized` finding, never an exception. |
| `CENSYS_TIMEOUT` | `15` (seconds) | Passed into the shared `HttpClient`. |
| `CENSYS_BASE_URL` | `https://search.censys.io/api` | Override for testing/self-hosted proxies. |

## Normalization strategy

Censys's `/v2/hosts/{ip}` result maps onto the **same** canonical models
Shodan already uses — no new fields added:

| Censys field(s) | Canonical shape |
|---|---|
| `services[].port/.transport_protocol/.service_name`, `.software[0].{product,version}` | `ExposureAsset(asset_type="open_port", …)` |
| `services[].tls.certificates.leaf_data.{subject_dn,issuer_dn,fingerprint}` | `ExposureAsset(asset_type="certificate", …)` |
| `dns.reverse_dns.names[]` | `ExposureAsset(asset_type="hostname", …)` |
| `autonomous_system.{asn,name}` | `ExposureEvidence(type="asn"/"organization", …)` |
| `location.{country,city}` | `ExposureEvidence(type="country"/"city", …)` |
| `last_updated_at` | `ExposureEvidence(type="last_seen", …)` |

`normalize()` accepts either the full API envelope (`{"result": {...}}`) or
a bare result object, for robustness. Raw Censys JSON never leaves the
provider — only canonical `ExposureFinding` objects do.

## Health strategy

Identical state machine to Shodan, probed against Censys's own lightweight
account endpoint (`/v2/account`) instead of a query-consuming search:
`CENSYS_ENABLED=false` → `DISABLED`; missing credentials → `DEGRADED`;
unreachable/timeout → `UNAVAILABLE`; 4xx/5xx → `DEGRADED`; 200 → `OPERATIONAL`.

## Caching strategy

Identical to Shodan: in-memory, one-hour TTL, keyed by `entity_type:value`,
only `OK`/`NOT_FOUND` cached. A rate-limited or auth-failed lookup always
retries on the next call rather than replaying a cached failure.

## Testing summary

`backend/tests/exposure/test_censys_provider.py` — 32 tests, the same
coverage shape as `test_shodan_provider.py`: metadata, IPv4/IPv6 success with
full normalization, Basic-auth header construction, a no-data host (category
`None`), private/invalid IP and unsupported-type short-circuits, missing/
partial credentials, 401/403/404/429/5xx/timeout/network/malformed-JSON
mapping, a missing `result` key, health across all four states, the
`CENSYS_ENABLED` env var, `configuration()` never leaking credentials, and
the cache (hit/TTL-expiry/non-caching-of-failures/`NOT_FOUND`-is-cached).

`test_registry.py`, `test_service.py`, and `test_api.py` updated for two
default providers, plus the explicit framework-validation test:
`TestDefaultRegistry.test_ipv4_routes_to_both_shodan_and_censys` proves one
IPv4 lookup through the **unmodified** `ExposureService` routes to and merges
both providers, in deterministic order, with zero findings dropped.

New `tests/exposure/conftest.py` isolates the whole suite from local `.env`
credential state (see "Architecture decisions" above).

**Exposure suite: 141 tests** (was 105). **Full backend suite: 1,758 passed,
1 skipped** (was 1,722). Ruff and mypy (strict) clean across 134 source
files (was 133 — the one new `censys.py`). **Frontend: 98 tests, unchanged**
— zero frontend files were modified this phase. Browser-verified
end-to-end (Playwright, mocked two-provider API response): Provider Status
shows both "Censys Status" and "Shodan Status"; the results section renders
both finding cards side by side with their own assets/evidence/references —
all through Phase 5.1's existing, unmodified components.

## Performance summary

No change to any existing hot path beyond what Phase 5.1 already introduced
(one health probe per registered provider per status call; one lookup per
provider per `?value=` call, cached for an hour). Two providers now run
concurrently via the same `asyncio.gather` Phase 5.0 already used for one.

## Documentation summary

New: this document. Updated: `README.md` (Roadmap, Exposure config table
gains the five `CENSYS_*` variables, Health & Monitoring section),
`CHANGELOG.md` (`[Unreleased]` entry).

## Confirmations

- **No Threat Intelligence changes** — every file under `providers/` is
  byte-for-byte unmodified; `CensysProvider` only *imports* `providers/http.py`
  (same disclosed exception `ShodanProvider` already established).
- **No Knowledge changes** — `reference/` untouched.
- **No Investigation changes** — `investigation/` and its frontend
  components untouched.
- **No Reasoning changes** — `reasoning/` untouched.
- **No Detection changes** — `detection/` untouched.
- **No Detection Knowledge changes** — `detection_library/` untouched.
- **No Operational Dashboard changes** — `system/`, `app/dashboard/`,
  `components/dashboard/` untouched.

Verified via `git status --porcelain` grep against every frozen path — no
matches. No frontend file was touched at all this phase.

## Not built (future phases)

GreyNoise, SecurityTrails, FOFA, LeakIX, BinaryEdge, CriminalIP, HIBP,
IntelligenceX, domain/email exposure, and `InvestigationSummary` integration
all remain unstarted, later milestones.
