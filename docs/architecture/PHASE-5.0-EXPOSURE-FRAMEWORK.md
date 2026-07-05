# Phase 5.0 — Exposure Intelligence Framework

## Status

Complete. Architecture only — **zero concrete providers**. This is the first
milestone of ThreatLens v2.0; every v1.x subsystem (Core Platform, Detection
Engineering, the Operational Platform) is frozen and untouched.

## Purpose

Threat Intelligence (`providers/`) answers **"is this IOC malicious?"**
Exposure Intelligence answers **"where is this entity exposed?"**

| Entity | Exposure facts |
|---|---|
| IP | open ports → certificates → passive DNS → hosting → ASN → services |
| Email | breaches → credential exposure → paste sites → leak history |
| Domain | subdomains → certificate transparency → DNS history → hosting |

Exposure Intelligence is **purely descriptive** — it never scores, never
judges maliciousness, and remains a separate framework from Threat
Intelligence at every layer (no shared models, no shared registry, no shared
import in either direction).

## Architecture decisions

- **Mirrors `providers/` (Phase 1.2's framework-only milestone), not a
  fresh design.** Same shape — closed-vocabulary enums, a frozen-Pydantic
  canonical finding model, an ABC provider interface with stub network
  methods, a registry that also routes, a pure aggregation function — because
  that pattern already proved out (TI shipped four real providers against it
  unchanged). Only the requested, leaner file layout differs: routing lives
  on `ExposureRegistry` itself rather than a separate router module, since
  there is nothing to route to yet.
- **One enum (`ExposureCapability`) instead of two.** TI separates
  `ProviderCapability` (routing) from `Evidence.type` (free-form). With zero
  real payloads to shape a free-form vocabulary against, reusing one closed
  enum for both a provider's declared capability and a finding's category is
  the honest choice for a framework-only phase — revisit once Phase 5.1
  providers exist.
- **`ExposureFinding` carries status, mirroring `IntelligenceResult`.**
  Attribution and outcome (ok/not_found/unsupported/error/…) live on one
  object per provider, so a failed or silent provider never blocks another's
  data and the summary keeps every provider's attribution, not just the
  successful ones.
- **The service always runs the real aggregation path.** `ExposureService.
  investigate()` calls `registry.route()` then merges whatever comes back.
  With zero providers registered, `route()` returns `()` and the merge
  produces a well-formed empty summary — not a hardcoded stub response. A
  Phase 5.1 provider changes the *data*, never this code path.
- **Framework version starts at `0.1.0`, not `1.0`.** Unlike the Reasoning
  and Detection Engines (frozen at `1.0` only after their content was
  validated end-to-end against real scenarios), this framework has no
  provider content to validate yet. It moves to `1.0` the same way those did
  — after Phase 5.1+ providers ship and the whole subsystem is validated,
  never as a version bump alone.
- **Cache and config are interfaces/settings only.** `ExposureCache` (ABC) +
  `InMemoryExposureCache` (the only concrete backend) are not wired into
  `ExposureService` yet — there is nothing to cache without a live provider.
  `ExposureConfig.from_env()` resolves `EXPOSURE_ENABLED` /
  `EXPOSURE_CACHE_ENABLED` / `EXPOSURE_TIMEOUT` /
  `EXPOSURE_RATE_LIMIT_PER_MINUTE`, all currently unread by any code path.

## Dependency direction

```
entities/  ←───────────────  exposure/  (models, provider, registry, config, cache, normalize, summary, service)
                                  ↑
                          exposure/providers/  (empty — Phase 5.1+)
```

`exposure/` imports only from `entities/` (the `Entity`/`EntityType`
contract every framework shares). It does **not** import from `providers/`,
`reference/`, `reasoning/`, `detection/`, `detection_library/`, `ai/`, or
`system/` — and nothing in those packages imports from `exposure/`. The one
integration point is `api/app.py`, which mounts `GET /api/v1/exposure`
exactly as it mounts every other subsystem's routes, without threading
Exposure Intelligence through `/investigate`.

## Framework design

`backend/src/threatlens/exposure/`:

| File | Role |
|---|---|
| `models.py` | Closed vocabularies (`ExposureCapability`, `ExposureStatus`, …) + frozen Pydantic models (`ExposureProviderMetadata`, `ExposureFinding`, `ExposureAsset`, `ExposureEvidence`, `ExposureReference`, `ExposureStatistics`, `ExposureMetadata`, `ExposureSummary`). |
| `exceptions.py` | `ExposureError` base, `DuplicateExposureProviderError`, `ExposureConfigurationError`. |
| `provider.py` | `ExposureProvider` ABC — `metadata` is the only abstract member; `lookup`/`normalize`/`configuration` are stubs a Phase 5.1 provider implements; `health()` and `safe_lookup()` (never-raises wrapper) are already real. |
| `registry.py` | `ExposureRegistry` — register/get/discover, plus `route()`/`route_type()` (folded in; no separate router module). `build_default_registry()` returns an empty registry. |
| `config.py` | `ExposureConfig` (env-driven, mirrors `ai/config.py`). |
| `cache.py` | `ExposureCache` ABC + `InMemoryExposureCache` default (interfaces only — no Redis, no persistence). |
| `normalize.py` | Generic payload-parsing helpers (mirrors `providers/_normalize.py`) for a future provider to reuse. |
| `summary.py` | `merge_findings()` — the aggregation function (mirrors `providers/aggregation.py::aggregate()`); `merge_assets()` for a future flat-asset view. |
| `service.py` | `ExposureService.investigate(entity) -> ExposureSummary`; `EXPOSURE_FRAMEWORK_VERSION`. |
| `providers/` | Empty — a future `ShodanProvider`/`CensysProvider`/etc. registers here. |

## Provider interface

A future provider implements exactly what TI providers already prove out:

```python
class ShodanProvider(ExposureProvider):
    @property
    def metadata(self) -> ExposureProviderMetadata: ...
    async def lookup(self, entity: Entity) -> ExposureFinding: ...   # calls Shodan, delegates to normalize()
    async def normalize(self, raw: Any) -> ExposureFinding: ...      # raw JSON → canonical finding
    async def configuration(self) -> dict[str, Any]: ...             # e.g. {"api_key_configured": True}
```

`health()` and `safe_lookup()` come from the base class unchanged — no
provider needs to reimplement graceful failure.

## Registry design

`ExposureRegistry` combines what TI splits across `ProviderRegistry` +
`ProviderRouter`: unique-name registration (`DuplicateExposureProviderError`
on clash), priority-then-name ordered discovery, and routing
(`route`/`route_type`) that filters on `enabled`, `supported_entity_types`,
and an optional `capability` — pure and synchronous, no network calls, no
global mutable state (tests build isolated registries).

## Summary model

`ExposureSummary` is the canonical, frozen output: `findings` (every routed
provider's attribution, successful or not), `references` (deduplicated by
URL across providers), `statistics` (`providers_queried`, `providers_ok`,
`total_findings` — findings that actually carry data, `total_assets`,
`categories`), and `metadata` (entity, timestamp, framework version). The
shape does not change when Phase 5.1 adds real providers — only the values
inside `findings` do.

## Testing summary

`backend/tests/exposure/` — 66 tests, offline, zero network, zero live
providers: model serialization/classmethods, the provider ABC's stub/health/
`safe_lookup` behavior via minimal test doubles, registry registration and
routing (including disabled-provider exclusion and capability narrowing),
config defaults/overrides, the in-memory cache (including TTL expiry via an
injectable fake clock), `merge_findings`/`merge_assets` aggregation, the
service's empty-registry and fake-provider paths (including a provider whose
`lookup` raises, proving `safe_lookup` never propagates), and the
`GET /api/v1/exposure` endpoint's shape and isolation from the TI path.
Full backend suite: **1,683 passed, 1 skipped** (was 1,617 before this
phase). Ruff and mypy (strict) clean across 132 source files.

## Performance summary

No network I/O anywhere in this phase — every check is in-memory or a
closed-vocabulary lookup. `GET /api/v1/exposure` is a single `len()` call
over an empty registry. Nothing here is on the `/investigate` hot path.

## Future provider roadmap (not built — do not begin)

Phase 5.1+ registers concrete providers against this unmodified contract:
Shodan, Censys, GreyNoise, HIBP, SecurityTrails, IntelligenceX, BinaryEdge,
FOFA, CriminalIP, LeakIX. Each is a `ExposureProvider` subclass wired into
`registry.build_default_registry()` — exactly how `providers/defaults.py`
added AbuseIPDB/OTX/MalwareBazaar/URLhaus after Phase 1.2. Integrating
`ExposureSummary` into `InvestigationSummary` (or a parallel investigation
surface) is explicitly deferred until real provider data exists to shape
that decision.
