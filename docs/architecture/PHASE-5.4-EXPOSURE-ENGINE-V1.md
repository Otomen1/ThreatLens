# ThreatLens — Exposure Engine v1.0 (Phase 5.4: Validation & Freeze)

## Status

**Frozen at v1.0.** This phase adds **no** new providers, features, or
architectural changes. It validates the entire Exposure Intelligence
subsystem end-to-end across all three providers (Shodan, Censys, GreyNoise),
protects its output with a byte-stable golden snapshot, benchmarks its
scaling and caching, reviews the architecture for consistency, and —
validation having succeeded — freezes the engine at
`EXPOSURE_FRAMEWORK_VERSION = "1.0"`.

Like the Reasoning Engine freeze (Phase 3.15) and the Detection Engine
freeze (Phase 4.5), the freeze is a contract: any future change to routing,
merge, or statistics semantics must regenerate the golden snapshot, bump the
engine version, and document the change. **The only production-code change
in this entire phase is the version constant itself** — `service.py`'s
`EXPOSURE_FRAMEWORK_VERSION`, from `"0.1.0"` to `"1.0"`. Every other file
under `exposure/` is byte-for-byte unmodified.

## 1. What the engine is

The Exposure Engine is the framework spanning `exposure/registry.py`,
`exposure/service.py`, and `exposure/summary.py`: given a classified entity,
it routes to every enabled, entity-type-matching provider, fans them out
concurrently, and merges their findings into one canonical
`ExposureSummary` — never scoring, never judging maliciousness, purely
descriptive. Three concrete providers are registered by default: Shodan and
Censys (open ports, certificates, hosting/ASN, IPv4/IPv6), and GreyNoise
(internet-noise/business-service reputation, IPv4 only).

## 2. Pipeline (unchanged this phase)

```
Entity (already classified)
  └─ ExposureService.investigate(entity)
       ├─ registry.route(entity)              → enabled, type-matching providers, priority-then-name order
       ├─ asyncio.gather(*safe_lookup(entity)) → concurrent, exception-safe per provider
       └─ merge_findings(...)                  → ExposureSummary{findings, references (deduped), statistics, metadata}
```

## 3. Validation approach — fake providers, not live accounts

Real per-provider correctness (Shodan/Censys/GreyNoise HTTP mapping,
parsing, auth, health) is already covered by 187 tests in
`tests/exposure/test_*_provider.py`, none of which this phase touches. This
freeze validates the **framework** — routing, concurrent fan-out, merge,
statistics, ordering, determinism, and the frontend/API contract — across
provider *combinations*, using a controllable `FakeExposureProvider`
(`tests/exposure_validation/fakes.py`) that returns canned findings or
raises, under the real provider names (`shodan`, `censys`, `greynoise`) so
ordering still exercises the real priority-then-name tiebreak. No network,
no HTTP mocking, no live account — matching the phase's "no live Internet
access, all responses must be mocked" requirement.

## 4. Validation corpus

`tests/exposure_validation/corpus.py` — **153** deterministic scenarios,
built parametrically (mirroring `tests/detection/corpus.py`'s approach):

| Group | Count | Coverage |
|---|---:|---|
| 12 categories × 12 provider-matrix shapes | 144 | Public infrastructure, cloud providers, CDNs, VPNs, internet scanners, known-malicious hosts, known-benign hosts, residential, enterprise, government, university, and hosting-provider labels — each × every single/pair/triple provider combination, disabled providers, all-disabled, one timeout, one auth failure, one malformed response, and mixed outcomes |
| Standalone special cases | 9 | Empty registry, unsupported entity type, a provider that raises (crash safety), all-not-found, all-rate-limited, cross-provider reference de-duplication, IPv6 routing excluding GreyNoise (its real IPv4-only scope), a large finding (20 evidence + 15 assets), non-default-priority ordering (proving priority, not just name, drives order) |

Category labels are descriptive only — every entity value is a synthetic
RFC 5737 documentation address (`192.0.2.0/24`), never a real allocated IP,
since every finding is entirely canned regardless of the label attached to
it (a "known malicious host" scenario is exactly as fake as a "known benign
host" one — no real-world host is ever named or implicated).

Both `shodan`/`censys` (OPEN_PORTS/CERTIFICATES) and `greynoise`
(INTERNET_NOISE) contribute distinct categories on success, so
`statistics.categories` aggregation is exercised as a genuine multi-valued
set, not one repeated value.

## 5. Validation report

`harness.validate_scenario` runs every scenario through the real,
unmodified `ExposureRegistry` + `ExposureService` and asserts, per scenario:

| Invariant | Check |
|---|---|
| Routing | `providers_queried` matches enabled, type-matching providers only |
| Merge / ordering | Finding order is deterministic priority-then-name, never registration order |
| Statistics | `providers_ok`, `total_findings`, `total_assets`, `categories` match hand-derived expectations |
| Entity identity | Never silently changed across the summary or any finding |
| No duplicate references | `summary.references` has no two entries sharing a URL |
| No duplicate evidence/assets | No finding carries two evidence or asset entries with the same `(type, value)` |
| Serialization | `ExposureSummary.model_validate_json(summary.model_dump_json()) == summary` |
| Frontend/API contract | Exact key sets at the summary, statistics, metadata, and finding level — matching `frontend/lib/api.ts`'s TS types |

**Result: 0 violations across all 153 scenarios.** No provider, service, or
summary code required any change to pass — the corpus validated the
existing implementation, it did not drive new work.

A representative subset (5 of the 153, spanning success/mixed/empty/
unsupported/crash-safety) is additionally driven through the real
`GET /api/v1/exposure` HTTP endpoint (`TestApiContract`), proving the
contract survives the FastAPI layer too, without paying for 153 HTTP
round-trips on top of the already-exhaustive model-level checks.

## 6. Determinism

`snapshot()` re-runs a scenario and compares a content-level projection
(entity, statistics, references, and every finding's provider/status/
category/evidence/assets/references/error). **153/153 scenarios are
identical across repeated runs.**

One field is deliberately excluded from the projection:
`metadata.generated_at`. `ExposureService.investigate()` takes no
injectable clock (unlike `reasoning.reason(..., now=...)` or
`detection.generate`'s timestamp-independent identity), so this one field
is wall-clock-derived — exactly the same shape of exclusion Reasoning and
Detection already apply to their own `generated_at`, not a new gap this
phase introduces. Every finding's `fetched_at` **is** included and stable,
because the corpus's fake providers set it to a fixed constant rather than
`datetime.now()` — mirroring how each real provider's own `_fail`/
`_not_found`/`_unsupported` paths already leave it `None` (only their
`_build`-style success path stamps a live timestamp, which is why the
canonical models correctly type it as optional). No randomness, no UUID —
`ExposureSummary`/`ExposureFinding` carry no ID field of that kind at all.

## 7. Performance benchmark

`tests/exposure_validation/perf.py` — pure, offline, CPU-only (fake
providers, no real network — provider-side latency is out of scope for a
framework benchmark and was never measurable in this sandbox anyway; see
Phase 5.1-5.3). Representative run:

**`ExposureService.investigate` scaling** (3 fake providers registered):

| lookups | findings | median | µs / lookup | peak alloc |
|---:|---:|---:|---:|---:|
| 1 | 3 | 0.20 ms | 198.7 | 11.7 KiB |
| 10 | 30 | 0.72 ms | 72.4 | 16.7 KiB |
| 50 | 150 | 2.96 ms | 59.2 | 15.0 KiB |
| 100 | 300 | 5.68 ms | 56.8 | 15.1 KiB |

Per-lookup cost **decreases** 3.5× from n=1 to n=100 — the opposite of a
bottleneck. This reflects `asyncio.run`'s fixed event-loop setup/teardown
cost amortizing across more inner lookups, not the framework degrading;
routing, fan-out, and merge cost themselves are near-zero and dominated by
this fixed overhead at small n.

**Cache effectiveness** (`InMemoryExposureCache`, one repeated lookup
through a fake provider that actually wires the cache, mirroring every real
provider's own cache-check → miss → store pattern): cold (miss) 2.38 ms,
warm (hit) 0.14 ms — **16.6× speedup**. The simulated 2 ms "fetch" cost is a
benchmark stand-in for real provider I/O (unmeasurable here — no live
account); the speedup demonstrates the shared cache abstraction itself
works, independent of any one provider's real latency.

**`merge_findings` in isolation** (no provider I/O at all — realistic usage
merges ~3 findings, but this stress-tests scaling the same way Detection's
benchmark ran `generate()` up to 1000 findings even though real
investigations are far smaller):

| findings | median | µs / finding | peak alloc |
|---:|---:|---:|---:|
| 1 | 0.008 ms | 7.7 | 3.0 KiB |
| 10 | 0.013 ms | 1.3 | 3.2 KiB |
| 50 | 0.036 ms | 0.7 | 4.1 KiB |
| 100 | 0.064 ms | 0.6 | 5.3 KiB |

**No bottleneck at any measured scale. No optimization was performed** (none
is justified — every number here is sub-millisecond for realistic usage of
1-3 providers).

## 8. Golden regression

`tests/exposure_validation/golden.json` snapshots every scenario: entity,
statistics, deduplicated reference URLs, and per-finding
provider/status/category/evidence/assets/references/error (excluding the
one wall-clock field, §6). `test_golden_regression` fails on any drift and
names the drifted scenarios. Regeneration is deliberate and gated:

```
THREATLENS_UPDATE_GOLDEN=1 pytest tests/exposure_validation/test_exposure_freeze.py::test_golden_regression
```

The CI **golden-regression job** now also runs `tests/exposure_validation`
alongside the reasoning benchmark, IOC-validation, detection-freeze, and
knowledge-library goldens, so any unintended change to exposure routing,
merge, or statistics turns CI red until the golden is intentionally
regenerated and the engine version is bumped.

## 9. Architecture review

The subsystem is internally consistent and required no redesign to pass
validation:

- **Provider abstraction remains sufficient.** `ExposureProvider`'s single
  abstract member (`metadata`) plus its shared `_fail`/`_not_found`/
  `_unsupported`/`safe_lookup` helpers were enough to build a fourth,
  purely test-local provider (`FakeExposureProvider`) with zero changes to
  the base class — the same reuse Shodan/Censys/GreyNoise already
  demonstrated for real integrations.
- **Canonical models remain sufficient.** This phase adds **zero** new
  model fields or enum values (contrast Phase 5.3's one documented
  `ExposureCapability.INTERNET_NOISE` addition) — 153 scenarios across
  every provider-matrix combination validated entirely within the existing
  `ExposureFinding`/`ExposureSummary`/`ExposureStatistics` shapes.
- **Registry remains sufficient.** Priority-then-name ordering (proven
  deterministic in Phase 5.0, reconfirmed by three real providers in Phase
  5.1-5.3) also correctly orders four/five ad-hoc fake providers with custom
  priorities (`special__priority_overrides_name_order`), and correctly
  excludes disabled or type-mismatched providers from routing regardless of
  how many are registered.
- **Cache abstraction remains sufficient.** `InMemoryExposureCache` needed
  no changes to demonstrate a 16.6× cold/warm speedup for a provider outside
  the three shipped ones — the interface, not just the three existing
  implementations, is what's validated here.
- **Service layer remains sufficient.** `ExposureService.investigate()` was
  driven completely unmodified by both the corpus harness and the API
  contract tests — the same object real requests use, not a stand-in.

## 10. Known limitations (honest, carried forward or newly documented)

- **No injectable clock on `ExposureService.investigate()`.** `generated_at`
  is wall-clock-derived and excluded from determinism/golden checks (§6) —
  the same accepted shape as Reasoning/Detection's own `generated_at`
  exclusion, not a regression. Adding one would be a real (if small) API
  change and was judged not "absolutely necessary" for this validation
  phase per its own scope.
- **`ExposureConfig`/`config.py` remains unwired into `ExposureService`**
  (true since Phase 5.0; unchanged by this phase, and not required by
  anything this freeze validates).
- **`merge_assets()` remains an unused, documented helper** in
  `summary.py` (offered for a future flat-asset consumer; not exercised by
  `merge_findings` itself, which keeps assets attached per-provider for
  provenance — by design, not an oversight).
- **Provider-side live-account verification remains outstanding** for all
  three providers (Shodan, Censys, GreyNoise) — this sandbox's egress
  policy has never permitted a real request to any of their APIs (Phase
  5.1-5.3). This freeze validates the framework around them, not their
  real-world endpoint/response-shape assumptions; that verification is
  still recommended before production reliance, exactly as each provider's
  own doc already discloses.

## 11. Public API contract — `GET /api/v1/exposure`

Unchanged by this phase. `{status, message, framework_version,
providers_registered, providers[], summary}`; `summary` (when a `value` is
given) is `ExposureSummary` unmodified. §5's `TestApiContract` drives five
representative scenarios through the real endpoint and confirms the
provider count, queried-provider count, and finding order all match the
model-level result exactly.

## 12. Testing summary

- **Backend total: 2126 passed, 1 skipped, 0 failed** (was 1804 before this
  phase; +322 new, all in `tests/exposure_validation/`, nothing elsewhere
  changed).
- **Exposure validation/freeze suite: 322 tests** — 153×2 per-scenario
  checks (invariants + determinism), corpus-shape/coverage/freeze-marker
  checks, golden regression, 6 API-contract tests, and 3 perf-harness smoke
  tests.
- **Exposure per-provider suite: 187 tests, unchanged** — this phase
  touches none of `tests/exposure/test_*_provider.py`, `test_registry.py`,
  `test_service.py`, `test_api.py`, `test_models.py`, or `test_summary.py`.
- Ruff and mypy (strict) clean across 135 source files (unchanged count —
  no new source file; only `service.py`'s version constant changed).
- Frontend: **98 tests, unchanged; build clean.** No frontend file was
  touched this phase — the task scoped frontend review to "unless API
  contract testing requires it," and the API contract was fully validated
  at the backend HTTP layer (§11) without needing to drive a browser.

## 13. Freeze checklist

- [x] ~150-scenario corpus (153) covering 12 realistic categories × every
      provider-matrix combination, plus 9 standalone edge cases.
- [x] Per-scenario invariants (routing, merge, ordering, statistics, no
      duplicate references/evidence/assets, serialization, frontend/API
      contract) — 0 violations.
- [x] Determinism verified for all 153 scenarios (content-level, wall-clock
      field excluded per documented, precedented convention).
- [x] Golden snapshot for every scenario; CI-gated against drift.
- [x] Performance benchmarked (scaling, cache effectiveness, isolated merge
      cost); no bottleneck; no optimization performed.
- [x] Architecture reviewed — provider/model/registry/cache/service
      abstractions all sufficient; no redesign performed.
- [x] Backend suite 2126 passed/1 skipped; frontend 98 passed; both green.
- [x] `EXPOSURE_FRAMEWORK_VERSION = "1.0"`.

## 14. Freeze recommendation

**Readiness: 9.5 / 10. Recommendation: GO — freeze Exposure Intelligence at
v1.0.** The framework is pure at the routing/merge layer, deterministic
(module a documented, precedented timestamp exclusion), fully covered by a
153-scenario corpus with zero invariant violations, protected by a CI-gated
golden snapshot, and benchmarked with no bottleneck at any realistic scale.
The half-point reserved mirrors §10 exactly: real provider endpoints remain
unverified against live accounts (a sandbox constraint disclosed since Phase
5.1, not introduced here), and the service layer's clock is not
dependency-injected. Neither blocks the freeze — both are pre-existing,
documented, and outside this phase's validated surface (the framework's own
routing/merge/aggregation behavior, which is what "Exposure Engine v1.0"
actually names). Future provider additions follow the same contract as the
Reasoning and Detection Engine freezes: regenerate the golden, bump the
version, document the change.
