# Phase 5.2 — Censys Exposure Provider

## Status

Complete. The second concrete Exposure Intelligence provider — and the
framework-validation milestone: proving the Phase 5.0 framework and Phase
5.1's per-provider pattern both scale to multiple providers with **no
architectural change**. Every other subsystem remains frozen and untouched.

**Phase 5.2.1 (compatibility migration, same scope):** adds Personal Access
Token (Bearer) authentication against Censys's current Platform API,
preferred over the original legacy Basic-auth (API ID + Secret) mode, which
remains fully supported for backward compatibility. See "Personal Access
Token migration (5.2.1)" below.

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
| `CENSYS_PERSONAL_ACCESS_TOKEN` | unset | **Preferred.** From https://search.censys.io/account/api. When set, used as `Authorization: Bearer <token>` against the Platform API — takes precedence over the legacy pair below. |
| `CENSYS_API_ID` | unset | Legacy. Used only when no PAT is set. |
| `CENSYS_API_SECRET` | unset | Legacy, paired with `CENSYS_API_ID`. |
| `CENSYS_TIMEOUT` | `15` (seconds) | Passed into the shared `HttpClient`. |
| `CENSYS_BASE_URL` | auth-mode-dependent | Override for testing/self-hosted proxies. Default is `https://api.platform.censys.io` when using a PAT, `https://search.censys.io/api` when using the legacy pair. |

No credentials configured at all (neither PAT nor the legacy pair) → every
lookup returns a structured `unauthorized` finding, never an exception.

## Personal Access Token migration (5.2.1)

Censys has moved to Personal Access Tokens (Bearer auth) against a unified
Platform API, superseding the legacy API-ID/Secret Basic-auth model Phase
5.2 originally shipped against. `CensysProvider` now supports both, resolved
once at construction:

1. `CENSYS_PERSONAL_ACCESS_TOKEN` set → Bearer auth, Platform API.
2. Else `CENSYS_API_ID` + `CENSYS_API_SECRET` both set → Basic auth, legacy
   Search API v2 — **unchanged from Phase 5.2**, kept for backward
   compatibility.
3. Else → not configured (`unauthorized` finding; `health()` → `DISABLED`).

**Health semantics changed for this provider specifically:** missing
credentials now reports `DISABLED` ("not set up") rather than `DEGRADED`
("configured but rejected") — a deliberate distinction requested for this
migration. `ShodanProvider` is intentionally left as-is (missing key →
`DEGRADED`), so the two providers are no longer symmetric on this one point;
this asymmetry is a known, accepted tradeoff of a provider-scoped migration,
not an oversight.

**Honesty note:** the Platform API endpoint (`/v3/global/asset/host/{ip}`)
and health probe (`/v3/organizations`) are a best-effort mapping from
Censys's documented Platform API conventions — this sandbox's egress policy
blocks arbitrary third-party API hosts (the same wall hit earlier verifying
the Shodan key), so nothing in this whole framework, including this new
path, has been exercised against a live upstream. The response-unwrapping
helper defensively accepts either the legacy flat `result` shape or a
Platform-style `result.host` nesting, and every field access already
tolerates absence (same as `ShodanProvider`) — a wrong guess about the exact
Platform response shape degrades to a sparse "ok" finding, never a crash.
Real-world verification against a live Platform account is recommended
before depending on this path in production.

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

`CENSYS_ENABLED=false` → `DISABLED`; no credentials configured at all →
`DISABLED`; unreachable/timeout → `UNAVAILABLE`; configured but rejected
(4xx/5xx) → `DEGRADED`; 200 → `OPERATIONAL`. Probed against
`/v3/organizations` (PAT mode) or `/v2/account` (legacy mode) — a
lightweight endpoint, not a query-consuming search, in both cases. See
"Personal Access Token migration" above for why missing-credentials differs
from `ShodanProvider`'s `DEGRADED`.

## Caching strategy

Identical to Shodan: in-memory, one-hour TTL, keyed by `entity_type:value`,
only `OK`/`NOT_FOUND` cached. A rate-limited or auth-failed lookup always
retries on the next call rather than replaying a cached failure.

## Testing summary

`backend/tests/exposure/test_censys_provider.py` — 46 tests (32 from Phase
5.2, 14 added for the PAT migration), covering both auth modes: metadata,
IPv4/IPv6 success with full normalization (both the flat legacy shape and
the nested `result.host` Platform shape), Bearer- and Basic-auth header
construction, endpoint/base-URL selection per mode, PAT-takes-precedence
when both are configured, a no-data host (category `None`), private/invalid
IP and unsupported-type short-circuits, missing/partial legacy credentials
and a missing PAT, 401/403/404/429/5xx/timeout/network/malformed-JSON
mapping for both modes, a missing `result` key, health across all four
states for both modes (including the `DISABLED`-not-`DEGRADED` change on
missing credentials), the `CENSYS_ENABLED` env var, `configuration()`
reporting `auth_mode` without ever leaking a token/secret, and the cache
(hit/TTL-expiry/non-caching-of-failures/`NOT_FOUND`-is-cached, confirmed
auth-mode-agnostic).

`test_registry.py`, `test_service.py`, and `test_api.py` updated for two
default providers, plus the explicit framework-validation test:
`TestDefaultRegistry.test_ipv4_routes_to_both_shodan_and_censys` proves one
IPv4 lookup through the **unmodified** `ExposureService` routes to and merges
both providers, in deterministic order, with zero findings dropped. New
`tests/exposure/conftest.py` clears `CENSYS_PERSONAL_ACCESS_TOKEN` (and the
legacy pair) before every test alongside the vars it already cleared, so a
real token in a local `.env` never leaks into test outcomes.

New `tests/exposure/conftest.py` now also isolates the suite from a local
`.env`'s `CENSYS_PERSONAL_ACCESS_TOKEN`, alongside the vars it already
cleared for Shodan and legacy Censys credentials.

**Exposure suite: 151 tests** (was 141 after Phase 5.2, 105 after Phase 5.0).
**Full backend suite: 1,768 passed, 1 skipped** (was 1,758). Ruff and mypy
(strict) clean across 134 source files (unchanged — no new files this
migration). **Frontend: 98 tests, unchanged** — zero frontend files touched;
the existing `disabled` status value and its rendering were already generic
from Phase 5.1, so Censys's new `DISABLED`-on-no-credentials state renders
correctly with no frontend code change. Phase 5.2's original browser
verification (Provider Status showing both providers, results rendering
side by side) remains valid and was not re-run, since nothing in the
frontend or the API response shape changed.

## Performance summary

No change to any existing hot path beyond what Phase 5.1 already introduced
(one health probe per registered provider per status call; one lookup per
provider per `?value=` call, cached for an hour). Two providers now run
concurrently via the same `asyncio.gather` Phase 5.0 already used for one.

## Documentation summary

This document, extended in place with the "Personal Access Token migration
(5.2.1)" section rather than a separate file (a compatibility migration, not
a new phase). `README.md` (Exposure config table gains
`CENSYS_PERSONAL_ACCESS_TOKEN`, notes the new default-base-URL behavior),
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
