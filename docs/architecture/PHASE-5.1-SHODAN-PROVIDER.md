# Phase 5.1 — Shodan Exposure Provider

## Status

Complete. The first concrete Exposure Intelligence provider. Every other
subsystem — Core Platform, Detection Engineering, the Operational Platform,
and the Phase 5.0 Exposure Intelligence Framework itself — is unchanged in
shape; this phase only populates the extension seam Phase 5.0 reserved.

## Purpose

Phase 5.0 shipped the Exposure Intelligence Framework with zero providers.
This phase answers, for real, the framework's founding question for one
entity type: **"where is this IP exposed?"** — open ports, running services,
TLS certificates, hostnames/domains, and hosting/ASN facts, sourced from
[Shodan](https://www.shodan.io)'s Host API. Still purely descriptive: no
score, no reputation, no malicious/benign verdict. That remains Threat
Intelligence's separate question.

## Scope decision: IPv4/IPv6 only

`ShodanProvider` supports **only `IPV4`/`IPV6`**. Shodan's host lookup
(`/shodan/host/{ip}`) is IP-keyed; reporting exposure for a domain would
require an extra DNS-resolution hop the API doesn't expose as a single,
unambiguous call. Rather than guess at a multi-step design the task didn't
ask for, domain/hostname support is deferred — `ExposureProvider.supports()`
already returns a structured `UNSUPPORTED` finding (never an exception) for
any other entity type, so this is a clean, forward-compatible scope line,
not a gap.

## Architecture decisions

- **Reuses `providers/http.py`'s `HttpClient` — a deliberate, narrow, disclosed
  exception to Phase 5.0's "`exposure/` never imports from `providers/`" rule.**
  `HttpClient` carries zero Threat Intelligence types, models, registry, or
  business logic — it's a generic async transport wrapper (timeout + bounded
  retry-with-backoff over `httpx`) that TI happens to have built first.
  Duplicating it into a second HTTP layer was explicitly out of scope; importing
  the one that exists is honest reuse. Exposure Intelligence still shares zero
  models, zero registry, and zero provider logic with Threat Intelligence — the
  parts of the Phase 5.0 isolation guarantee that actually matter are intact.
  No file under `providers/` was modified to make this work.
- **Mirrors `providers/abuseipdb.py`'s proven shape for a single-IP-lookup
  provider**: constructor reads its own env vars with constructor-param
  overrides for testability; a private IP short-circuits to `NOT_FOUND`
  without a request; HTTP status codes map to structured statuses; `normalize()`
  derives entity identity from the raw payload for reuse outside `lookup()`.
- **`SHODAN_ENABLED` maps directly onto `ExposureProviderMetadata.enabled`** —
  a field and a routing filter (`ExposureRegistry.route_type`) Phase 5.0 already
  built and tested. No new enable/disable mechanism was needed. `ShodanProvider`
  is always registered by `build_default_registry()` (matching
  `providers/defaults.py`'s unconditional-registration precedent); a missing
  API key surfaces as a structured `UNAUTHORIZED` finding at lookup time, not
  by hiding the provider from the registry.
- **One finding, one (best-effort) category.** `ExposureFinding.category` is
  singular, but a single Shodan host record naturally spans ports, certificates,
  and hosting facts at once. Rather than force three findings out of one API
  call, the finding's `category` is decided per-response — `OPEN_PORTS` if any
  port is reported, else `HOSTING` if organization/ISP/ASN data exists, else
  `None` — while every fact is still preserved in full via free-form-typed
  `ExposureEvidence`/`ExposureAsset` entries. This is a revisit-when-more-providers-
  exist simplification, the same kind Phase 5.0 flagged for the single
  `ExposureCapability` enum.
- **Caching lives in the provider, not the service.** Phase 5.0 deliberately
  left `ExposureService` cache-free ("nothing to cache without a live
  provider"). Now that one exists, wiring a cache *policy* (key shape, TTL,
  what's cacheable) into the shared `ExposureService` would be a framework
  change affecting every future provider before a second one exists to justify
  the shape. Instead, `ShodanProvider` owns an `InMemoryExposureCache`
  (Phase 5.0's only concrete cache backend — no Redis, no database) directly:
  `OK`/`NOT_FOUND` results are cached for one hour; `TIMEOUT`/`RATE_LIMITED`/
  `ERROR`/`UNAUTHORIZED` are never cached, so a transient failure or a freshly
  fixed API key is retried on the very next lookup rather than stuck replaying
  a stale failure.
- **`health()` is overridden with a real, cheap probe.** The base class's
  `health()` (Phase 5.0) is a no-network stub. `ShodanProvider.health()` calls
  Shodan's lightweight `/api-info` endpoint (account/key validation, not a
  query-credit-consuming search) and maps the result onto the framework's
  existing `ExposureProviderStatus` vocabulary — `OPERATIONAL`/`DEGRADED`/
  `UNAVAILABLE`/`DISABLED` — matching the task's Healthy/Degraded/Offline/
  Disabled requirement without inventing new status values.
- **`GET /api/v1/exposure` gained an optional `value` query param** rather than
  a new endpoint, per an explicit instruction to extend the existing route. With
  no `value`, behavior is unchanged from Phase 5.0 (framework + now per-provider
  health status, `summary: null`). With `value`, the endpoint additionally runs
  `search.detect()` then `ExposureService.investigate()` and returns the merged
  `ExposureSummary` — still never integrated into `/investigate`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SHODAN_ENABLED` | `true` | Maps to `ExposureProviderMetadata.enabled`; `false` excludes Shodan from routing (a lookup then returns a well-formed, empty summary — zero providers queried). |
| `SHODAN_API_KEY` | unset | A free-tier-compatible key from https://account.shodan.io. Unset → every lookup returns a structured `UNAUTHORIZED` finding, never an exception. |
| `SHODAN_TIMEOUT` | `15` (seconds) | Passed straight into the shared `HttpClient`. |
| `SHODAN_BASE_URL` | `https://api.shodan.io` | Override for testing/self-hosted proxies. |

Same convention as every other provider in this codebase: read directly by
the provider's own constructor (`os.getenv`, overridable via constructor
kwargs for tests) — no shared provider-config object, no change to
`exposure/config.py` (that file remains framework-level settings, unread by
any provider).

## Normalization strategy

Shodan's host record maps onto the existing Phase 5.0 canonical models —
**no new fields were added to `ExposureFinding`/`ExposureAsset`/`ExposureEvidence`**:

| Shodan field(s) | Canonical shape |
|---|---|
| `data[].port`, `.transport`, `.product`, `.version`, `._shodan.module` | `ExposureAsset(asset_type="open_port", value=<port>, attributes={transport, product, version, service})` |
| `data[].ssl.cert` | `ExposureAsset(asset_type="certificate", value=<subject CN or fingerprint>, attributes={issuer, expires, fingerprint_sha256})` |
| `hostnames[]`, `domains[]` | `ExposureAsset(asset_type="hostname"/"domain", value=<name>)` |
| `data[].http.title` | `ExposureEvidence(type="http_title", …)` |
| `os`, `org`, `isp`, `asn`, `country_name`, `city` | `ExposureEvidence(type=<field>, …)` — present-fields-only |
| `last_update` | `ExposureEvidence(type="last_seen", observed_at=<parsed>)` |
| `vulns` (list or dict of CVE ids — Shodan uses both shapes depending on endpoint/plan) | `ExposureEvidence(type="vulnerability", …)` per id — a fact ("Shodan flagged a possible vulnerability"), never a severity or verdict |
| `tags[]` | `ExposureEvidence(type="tag", …)` per tag |

All of this happens inside `ShodanProvider._build()` — raw Shodan JSON never
leaves the provider; only canonical `ExposureFinding` objects do, per the
framework's `ExposureProvider.normalize()` contract.

## Health strategy

| Condition | `ExposureProviderStatus` |
|---|---|
| `SHODAN_ENABLED=false` | `DISABLED` |
| No `SHODAN_API_KEY` | `DEGRADED` ("API key not configured") |
| `/api-info` unreachable / times out | `UNAVAILABLE` |
| `/api-info` returns 401/403 or any 4xx/5xx | `DEGRADED` |
| `/api-info` returns 200 | `OPERATIONAL` |

`GET /api/v1/exposure` runs this for every registered provider on every call
(cheap — `/api-info` is a lightweight account-info endpoint, not a
query-credit-consuming search) and surfaces it as `providers: [{name,
display_name, status, detail}]`, the same status/health shape convention
used elsewhere in this codebase — without touching the Operational Dashboard
(`system/`) itself, which remains unmodified.

## Caching strategy

`ShodanProvider` owns an `InMemoryExposureCache[ExposureFinding]` (Phase
5.0's in-memory backend — no Redis, no database, no persistence across
restarts). Key: `f"{entity_type}:{entity_value.lower()}"`. Only `OK` and
`NOT_FOUND` findings are cached (one hour TTL); transient failures and auth
failures are never cached, so a rate-limited call or a since-fixed API key is
retried on the very next lookup rather than replaying a stale failure for an
hour.

## Testing summary

`backend/tests/exposure/test_shodan_provider.py` — offline, zero network,
zero real API key or Internet access required (every request goes through
`httpx.MockTransport`). Covers: metadata/supported-types, IPv4 and IPv6
lookup success with full normalization (assets, evidence, references,
category selection), a no-ports/no-hosting host (category `None`), private/
reserved IP short-circuiting without a request, invalid IP and unsupported
entity type without a request, missing API key, 401/403/404/429/5xx HTTP
mapping, timeout, network failure, malformed JSON, unexpected payload shape,
`health()` across operational/degraded/unavailable/disabled, the
`SHODAN_ENABLED` env var and constructor override, `configuration()` (and
that it never leaks the key), and the in-memory cache (hit avoids a second
request, TTL expiry via an injectable clock, transient/auth failures never
cached, `NOT_FOUND` is cached).

`backend/tests/exposure/test_registry.py`, `test_service.py`, and
`test_api.py` were updated for the new default-registry reality (Shodan
registered, not empty) and extended with: the `?value=` lookup path end-to-end
through the real FastAPI app (asserting a structured `unauthorized` finding
with no configured key — never a crash), a disabled-registry case proving the
endpoint still returns a valid empty summary, and per-provider health in the
status response shape.

**Exposure suite: 105 tests** (was 66 before this phase). **Full backend
suite: 1,722 passed, 1 skipped** (was 1,683). Ruff and mypy (strict) clean
across 133 source files (was 132 — the one new `shodan.py`).

Frontend: `frontend/lib/api.test.ts` gained coverage for
`exposureFrameworkStatus`'s new optional `value` parameter (URL encoding,
blank-value handling, abort propagation, error mapping). **Frontend suite: 98
tests** (was 92). `npm run build` clean, including the extended `/exposure`
route. The rebuilt Exposure page was driven end-to-end in a real browser
(Playwright) against a live backend for both the "not configured" path
(friendly `UNAUTHORIZED` message, no crash) and a mocked "configured with
results" path (ports/certificates/hostnames/evidence/references all render).

## Performance summary

No behavior change to any existing hot path. The new work is:
`GET /api/v1/exposure` now performs one cheap `/api-info` health check per
registered provider on every call (previously zero network calls), and,
only when `?value=` is supplied, one Shodan host lookup — cached in-memory
for repeat lookups of the same IP within an hour. Nothing here touches
`/investigate`, `/detect`, or any frozen subsystem's request path.

## Documentation summary

New: this document. Updated: `README.md` (Roadmap row, Exposure Intelligence
config table gains the four `SHODAN_*` variables, Health & Monitoring
subsection notes the real lookup capability), `CHANGELOG.md` (`[Unreleased]`
entry for Phase 5.1).

## Confirmations

- **No Threat Intelligence changes** — every file under `providers/` is
  byte-for-byte unmodified; `ShodanProvider` only *imports* `providers/http.py`
  (see "Architecture decisions" above for why that one import is a deliberate,
  disclosed exception, not a framework change).
- **No Knowledge changes** — `reference/` untouched.
- **No Investigation changes** — `investigation/` and every investigation
  frontend component untouched.
- **No Reasoning changes** — `reasoning/` untouched.
- **No Detection changes** — `detection/` untouched.
- **No Detection Knowledge changes** — `detection_library/` untouched.
- **No Operational Dashboard changes** — `system/`, `app/dashboard/`,
  `components/dashboard/` untouched.

## Not built (future phases)

Censys, GreyNoise, HIBP, SecurityTrails, IntelligenceX, BinaryEdge, FOFA,
CriminalIP, LeakIX, and domain/email exposure support all remain Phase 5.2+.
`ExposureSummary` integration into `InvestigationSummary` (or a parallel
investigation surface) is still explicitly deferred.
