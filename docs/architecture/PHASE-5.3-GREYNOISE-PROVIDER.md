# Phase 5.3 — GreyNoise Exposure Provider

## Status

Complete. The third concrete Exposure Intelligence provider — reconfirming,
after two independent providers already proved the pattern once, that the
Phase 5.0 framework scales to N providers with **no architectural change**.
Every other subsystem remains frozen and untouched. This phase also
introduces the framework's first new canonical model value since Phase 5.0
(`ExposureCapability.INTERNET_NOISE`), added narrowly and documented rather
than stretch-fit onto an existing one.

## Purpose

Adds [GreyNoise](https://viz.greynoise.io) as a third, independent source of
exposure context for IPv4 addresses — but a genuinely different *kind* of
fact than Shodan/Censys. Where those two answer "what is exposed on this
host" (open ports, services, certificates), GreyNoise answers "does the
Internet already know this IP as background noise or a recognized business
service" — reputation-flavored context, not scan-surface data. Still purely
descriptive: GreyNoise's own classification is reported as a quoted
third-party statement, never a ThreatLens-computed verdict.

## Framework validation summary

This phase's explicit goal was to confirm a *third*, structurally different
provider (single-key auth like Shodan, but a different capability, a
different auth header convention, IPv4-only, and zero assets) still requires
**no framework redesign**:

| Layer | Change required | What actually happened |
|---|---|---|
| `exposure/registry.py` | Add one provider to `build_default_registry()` | One `registry.register(GreyNoiseProvider())` line — the exact integration point Phase 5.0 reserved and Phase 5.2's doc already predicted would repeat |
| `exposure/service.py` | None | Completely unmodified — `ExposureService.investigate()` already fanned out to *every* routed provider and merged via `merge_findings()`; three providers exercise the same code path two already did |
| `exposure/summary.py` | None | `merge_findings()` already aggregated an arbitrary number of findings |
| Provider ordering | None | All three default to `priority=100`; the existing priority-then-name tiebreak (already proven in Phase 5.0/5.2) makes `censys` < `greynoise` < `shodan` sort deterministically, with no new ordering logic |
| `api/app.py` (`GET /api/v1/exposure`) | None | The endpoint already gathered `p.health()` over `_exposure_registry.providers` (plural) and called `_exposure_service.investigate()` once; a third provider just means the existing loops and the existing merge produce three entries instead of two |
| `frontend/app/exposure/page.tsx`, `ExposureFindingCard.tsx` | None | Both already iterate generically over `state.status.providers` and `summary.findings`; neither branches on provider name or `category`. Verified by mocking a three-provider API response (including GreyNoise's zero-assets, evidence-only shape) and confirming it renders correctly with zero frontend rendering-logic changes (browser-verified, screenshot in the deliverables) |
| `exposure/models.py` | None assumed; one minimal addition made | No existing `ExposureCapability` value described "internet-noise/business-service classification" — not a port/cert/hosting/breach fact. Rather than stretch an existing value to fit, exactly one new enum member (`INTERNET_NOISE`) was added, documented inline with the rationale. This is the one place this phase touches shared framework code, and it is additive only: no existing member changed meaning, no test asserted a closed/exhaustive enumeration (verified before adding) |

The only genuinely new *logic* is `GreyNoiseProvider` itself (`lookup`/
`normalize`/`health`/`configuration`) — a leaf, not a framework change. The
one shared-model touch is a single documented enum value, not a redesign.

## Architecture decisions

- **IPv4 only — not IPv4/IPv6 like Shodan/Censys.** This is GreyNoise's own
  API scope (`/v2/noise/context/{ip}` is IPv4-keyed), not a ThreatLens
  choice. `supported_entity_types = frozenset({EntityType.IPV4})` declares
  this the same declarative way every provider does; routing excludes
  GreyNoise for IPv6/domain entities automatically, with no router change.
- **`key` header, not `Authorization: Bearer`/`Basic`.** GreyNoise's own
  auth convention is a bare `key` header carrying the API key. Handled
  entirely inside `GreyNoiseProvider._auth_header()` — the shared
  `HttpClient.get()` already accepts arbitrary headers, so this required no
  framework change, exactly as Censys's `Basic`/`Bearer` headers didn't.
- **Zero assets, by design — evidence-only findings are a legitimate shape.**
  GreyNoise contributes no ports, certificates, or hostnames, so
  `ExposureFinding.assets` is always `[]` for this provider.
  `ExposureFinding.has_findings` is already `True` whenever evidence is
  non-empty regardless of assets, so this needed no model change — it
  surfaced a shape the canonical model already supported but no provider had
  exercised yet.
- **Reputation-flavored data, kept purely descriptive.** GreyNoise's
  `classification` field (`benign`/`malicious`/`unknown`) reads like a
  verdict, which is in tension with the framework's founding rule ("never
  judges maliciousness — that's Threat Intelligence's question"). Resolved
  the same way Shodan's CVE flags and Censys's ASN facts already were:
  reported as a quoted, attributed third-party statement inside
  `ExposureEvidence` (`"GreyNoise classification: malicious"`), never
  computed, stored, or exposed as a ThreatLens-owned score or band.
- **Deliberately asymmetric health semantics from Censys's PAT migration,
  matching Shodan instead.** Missing credentials report `DEGRADED`, not
  `DISABLED`. Phase 5.2.1 changed Censys specifically to `DISABLED` on
  missing credentials per an explicit request scoped to that migration;
  this phase's task did not request the same distinction for GreyNoise, so
  it follows Shodan's original, unchanged convention. The Censys exception
  stays scoped to Censys rather than silently spreading.
- **Reuses `providers/http.py`'s `HttpClient`** — the same disclosed,
  narrow exception to Phase 5.0's isolation rule that `ShodanProvider` and
  `CensysProvider` already established. No file under `providers/` is
  modified.
- **Provider-local cache, mirroring Shodan/Censys exactly** — an
  `InMemoryExposureCache` scoped to `GreyNoiseProvider`, one-hour TTL, only
  `OK`/`NOT_FOUND` cached. No change to the framework's cache abstraction.
- **Category selection**: `INTERNET_NOISE` if GreyNoise reports a
  classification, marks the IP as noise, or marks it RIOT; `None` otherwise
  — the same "derive from what came back, don't guess" heuristic Shodan and
  Censys already use for their own categories.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GREYNOISE_ENABLED` | `true` | Maps to `ExposureProviderMetadata.enabled`; `false` excludes GreyNoise from routing. |
| `GREYNOISE_API_KEY` | unset | From https://viz.greynoise.io/. Sent as a `key` header on every request. |
| `GREYNOISE_TIMEOUT` | `15` (seconds) | Passed into the shared `HttpClient`. |
| `GREYNOISE_BASE_URL` | `https://api.greynoise.io` | Override for testing/self-hosted proxies. |

No API key configured → every lookup returns a structured `unauthorized`
finding, never an exception; `health()` reports `DEGRADED`.

**Honesty note:** the Context API path (`/v2/noise/context/{ip}`) and health
probe (`/ping`) are a best-effort mapping from GreyNoise's documented API
conventions — this sandbox's egress policy blocks arbitrary third-party API
hosts (the same wall hit verifying Shodan and Censys), so nothing in this
provider has been exercised against a live upstream. Every field access
tolerates absence (same defensive pattern as Shodan/Censys), so a wrong guess
about an exact field name degrades to a sparser but still valid "ok" finding,
never a crash. Real-world verification against a live GreyNoise account is
recommended before depending on this path in production.

## Normalization strategy

GreyNoise's `/v2/noise/context/{ip}` result maps onto the **same** canonical
models Shodan and Censys already use — no new fields on any model, and the
one new enum value is the only vocabulary addition:

| GreyNoise field(s) | Canonical shape |
|---|---|
| `classification` | `ExposureEvidence(type="classification", …)` — quoted third-party statement, never a computed verdict |
| `noise` (bool) | `ExposureEvidence(type="internet_scanner", …)` when true |
| `riot` (bool) | `ExposureEvidence(type="business_service", …)` when true |
| `name`, `actor` (when not `"unknown"`) | `ExposureEvidence(type="name"/"actor", …)` |
| `vpn` / `vpn_service` | `ExposureEvidence(type="vpn", …)` |
| `metadata.{organization,asn,country,city}` | `ExposureEvidence(type="organization"/"asn"/"country"/"city", …)` |
| `metadata.tor` (bool) | `ExposureEvidence(type="tor", …)` when true |
| `last_seen` | `ExposureEvidence(type="last_seen", observed_at=parsed, …)` |
| `cve[]` | one `ExposureEvidence(type="vulnerability", …)` per CVE |
| `tags[]` | one `ExposureEvidence(type="tag", …)` per tag |
| `link` (or a derived report URL) | `ExposureReference(title="GreyNoise IP report", …)` |

`assets` is always `[]` — GreyNoise reports no ports, certificates, or
hostnames. `normalize()` derives entity identity from the record's `ip`
field, mirroring Shodan/Censys. Raw GreyNoise JSON never leaves the
provider — only canonical `ExposureFinding` objects do.

## Health strategy

`GREYNOISE_ENABLED=false` → `DISABLED`; no API key configured → `DEGRADED`
(unchanged Shodan-style convention — see "Architecture decisions" above for
why this differs from Censys's post-migration `DISABLED`); unreachable/
timeout → `UNAVAILABLE`; configured but rejected (401/403, or other 4xx/5xx)
→ `DEGRADED`; 200 → `OPERATIONAL`. Probed against `/ping`, a lightweight
endpoint, not a query-consuming lookup.

## Caching strategy

Identical to Shodan and Censys: in-memory, one-hour TTL, keyed by
`entity_type:value`, only `OK`/`NOT_FOUND` cached. A rate-limited or
auth-failed lookup always retries on the next call rather than replaying a
cached failure.

## Testing summary

`backend/tests/exposure/test_greynoise_provider.py` — 36 new tests covering:
metadata (IPv4-only, single `INTERNET_NOISE` capability), successful lookup
and full normalization (classification, noise, RIOT, name/actor, VPN, Tor,
metadata fields, last_seen, CVEs, tags, references), the zero-assets shape
asserted explicitly, category selection (present/absent across
classification/noise/riot combinations), `"unknown"` name/actor suppressed
as noise, the `key`-header request convention, private/invalid IPv4 and
unsupported-entity (including IPv6, since GreyNoise is IPv4-only unlike its
siblings) short-circuits with no request made, missing-key unauthorized
without a request, 401/403/404/429/5xx/timeout/network/malformed-JSON/
non-mapping-payload mapping, health across all four states, the
`GREYNOISE_ENABLED` env var, `configuration()` reporting status without ever
leaking the key, and the cache (hit/TTL-expiry/non-caching of
rate-limited/unauthorized failures/`NOT_FOUND`-is-cached).

`test_registry.py`, `test_service.py`, and `test_api.py` updated for three
default providers: `test_build_default_registry_registers_shodan_censys_and_greynoise`
asserts registration order `["censys", "greynoise", "shodan"]`;
`TestDefaultRegistry.test_ipv4_routes_to_all_three_providers` proves one IPv4
lookup through the **unmodified** `ExposureService` routes to and merges all
three providers, in deterministic order, with zero findings dropped;
`test_api.py`'s provider-count, health, and merged-summary assertions all
moved from two providers to three. `tests/exposure/conftest.py` extended to
clear `GREYNOISE_API_KEY`/`GREYNOISE_ENABLED`/`GREYNOISE_BASE_URL`/
`GREYNOISE_TIMEOUT` before every test, alongside the Shodan/Censys vars it
already cleared, so a real key in a local `.env` never leaks into test
outcomes.

**Exposure suite: 187 tests** (was 151 after Phase 5.2/5.2.1, 141 after Phase
5.2, 105 after Phase 5.0). **Full backend suite: 1,804 passed, 1 skipped**
(was 1,768). Ruff and mypy (strict) clean across 135 source files (was 134;
`+1` for `providers/greynoise.py`). **Frontend: 98 tests, unchanged** — no
frontend test file needed a change; the one frontend edit was a type-parity
addition (`ExposureCapability` gains `"internet_noise"` in `lib/api.ts`,
mirroring the backend enum) plus a one-line copy fix to the exposure page's
static IPv4/IPv6 support caption, neither of which is exercised by an
existing test. Browser-verified with Playwright against a mocked
three-provider response: Provider Status shows all three with correct
per-provider health, and the results list renders Censys/GreyNoise/Shodan
findings side by side — including GreyNoise's evidence-only, zero-assets
card rendering correctly through the fully generic `ExposureFindingCard`
with no component code change.

## Performance summary

No change to any existing hot path beyond what Phase 5.1/5.2 already
introduced (one health probe per registered provider per status call; one
lookup per provider per `?value=` call, cached for an hour). Three providers
now run concurrently via the same `asyncio.gather` Phase 5.0 already used
for one, then two.

## Documentation summary

This new document. `README.md` (Exposure Intelligence section gains
GreyNoise's configuration variables and provider description; provider count
references updated to three). `CHANGELOG.md` (`[Unreleased]` entry).

## Confirmations

- **No Threat Intelligence changes** — every file under `providers/` is
  byte-for-byte unmodified; `GreyNoiseProvider` only *imports*
  `providers/http.py` (same disclosed exception `ShodanProvider` and
  `CensysProvider` already established).
- **No Knowledge changes** — `reference/` untouched.
- **No Investigation changes** — `investigation/` and its frontend
  components untouched.
- **No Reasoning changes** — `reasoning/` untouched.
- **No Detection changes** — `detection/` untouched.
- **No Detection Knowledge changes** — `detection_library/` untouched.
- **No Operational Dashboard changes** — `system/`, `app/dashboard/`,
  `components/dashboard/` untouched.
- **No Exposure Framework redesign** — `exposure/service.py`,
  `exposure/summary.py`, `exposure/cache.py`, `exposure/provider.py`,
  `exposure/config.py`, and `api/app.py`'s exposure route are all
  byte-for-byte unmodified. The only shared-code touch is the single
  documented `ExposureCapability.INTERNET_NOISE` addition to
  `exposure/models.py`, described above.

Verified via `git status --porcelain` and a diff review against every frozen
path — no unexpected matches.

## Not built (future phases)

SecurityTrails, FOFA, LeakIX, BinaryEdge, CriminalIP, HIBP, IntelligenceX,
domain/email exposure, and `InvestigationSummary` integration all remain
unstarted, later milestones. Phase 5.4 is explicitly out of scope for this
phase.
