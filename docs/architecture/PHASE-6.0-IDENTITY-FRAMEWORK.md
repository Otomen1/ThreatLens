# Phase 6.0 — Identity Intelligence Framework

## Status

Complete. Architecture only — **zero concrete providers**. Opens a new
subsystem the same way Exposure Intelligence (Phase 5.0) and Threat
Intelligence (Phase 1.2) each began: the full framework — models, provider
interface, registry, config, cache, service, API endpoint, placeholder page —
with no live integrations. Every prior subsystem (Core Platform, Detection
Engineering v1.0, the Operational Platform, Exposure Engine v1.0) is frozen
and untouched.

## Purpose

Threat Intelligence (`providers/`) answers **"is this IOC malicious?"**
Exposure Intelligence (`exposure/`) answers **"where is this entity exposed?"**
Identity Intelligence answers **"what is known about this identity?"**

| Entity | Identity facts |
|---|---|
| Email | breaches → credential exposure → paste sites → linked accounts |
| Domain | directory profile → group membership → role assignments (org identity) |
| Account | MFA status → sign-in activity → first-party risk signals |

Identity Intelligence is **purely descriptive** — it never scores, never
judges compromise, and remains a separate framework from the other three at
every layer (no shared models, no shared registry, no shared import in any
direction). Where a future provider surfaces a first-party risk signal (e.g.
an IdP's own "risky user" flag), that is reported as a quoted, attributed
*third-party* fact inside an `IdentityEvidence` — never a ThreatLens-computed
verdict, the same discipline `exposure` already applies to GreyNoise's
classification.

## Architecture decisions

- **Mirrors `exposure/` (Phase 5.0's framework-only milestone), not a fresh
  design.** Same shape — closed-vocabulary enums, a frozen-Pydantic canonical
  finding model, an ABC provider interface with stub network methods, a
  registry that also routes, a pure aggregation function — because that
  pattern has now proved out twice (TI shipped four real providers against it;
  Exposure shipped three and froze at v1.0, both unchanged). Routing lives on
  `IdentityRegistry` itself rather than a separate router module, matching the
  exposure layout.
- **One enum (`IdentityCapability`) instead of two.** Like exposure, with zero
  real payloads to shape a free-form vocabulary against, one closed enum
  serves as both a provider's declared capability and a finding's category.
  The ten values span both breach-intelligence providers (HIBP-style:
  `breaches`, `credential_exposure`, `pastes`) and directory/IdP providers
  (Entra/Okta/AD-style: `directory_profile`, `group_membership`,
  `role_assignments`, `mfa_status`, `authentication_activity`,
  `risk_signals`, `linked_accounts`) — so a future provider of either kind
  fits without a vocabulary change.
- **`IdentityFinding` carries status, mirroring `ExposureFinding`.**
  Attribution and outcome (ok/not_found/unsupported/error/…) live on one
  object per provider, so a failed or silent provider never blocks another's
  data and the summary keeps every provider's attribution.
- **The service always runs the real aggregation path.**
  `IdentityService.investigate()` calls `registry.route()` then merges
  whatever comes back. With zero providers registered, `route()` returns `()`
  and the merge produces a well-formed empty summary — not a hardcoded stub.
  A Phase 6.1 provider changes the *data*, never this code path.
- **Framework version starts at `0.1.0`, not `1.0`.** Same convention as the
  Reasoning, Detection, and Exposure Engines: it moves to `1.0` only after
  Phase 6.1+ providers ship and the whole subsystem is validated end-to-end
  (as Exposure did in Phase 5.4), never as a version bump alone.
- **Cache and config are interfaces/settings only.** `IdentityCache` (ABC) +
  `InMemoryIdentityCache` (the only concrete backend) are not wired into
  `IdentityService` yet — there is nothing to cache without a live provider.
  `IdentityConfig.from_env()` resolves `IDENTITY_ENABLED` /
  `IDENTITY_CACHE_ENABLED` / `IDENTITY_CACHE_TTL` / `IDENTITY_TIMEOUT` /
  `IDENTITY_RATE_LIMIT_PER_MINUTE`, all currently unread by any code path. No
  secrets — provider credentials belong to each provider's own settings in a
  later phase.

## Dependency direction

```
entities/  ←───────────────  identity/  (models, provider, registry, config, cache, normalize, summary, service)
                                  ↑
                          identity/providers/  (empty — Phase 6.1+)
```

`identity/` imports only from `entities/` (the `Entity`/`EntityType` contract
every framework shares). It does **not** import from `providers/`,
`exposure/`, `reference/`, `reasoning/`, `detection/`, `detection_library/`,
`ai/`, or `system/` — and nothing in those packages imports from `identity/`.
The one integration point is `api/app.py`, which mounts `GET /api/v1/identity`
exactly as it mounts every other subsystem's routes, without threading
Identity Intelligence through `/investigate`.

## Framework design

`backend/src/threatlens/identity/`:

| File | Role |
|---|---|
| `models.py` | Closed vocabularies (`IdentityCapability`, `IdentityStatus`, `IdentityAuthType`, `IdentityProviderStatus`) + frozen Pydantic models (`IdentityProviderMetadata`, `IdentityProviderHealth`, `IdentityFinding`, `IdentityAsset`, `IdentityEvidence`, `IdentityReference`, `IdentityFindingError`, `IdentityStatistics`, `IdentityMetadata`, `IdentitySummary`). |
| `exceptions.py` | `IdentityError` base, `DuplicateIdentityProviderError`, `IdentityConfigurationError`. |
| `provider.py` | `IdentityProvider` ABC — `metadata` is the only abstract member; `lookup`/`normalize`/`configuration` are stubs a Phase 6.1 provider implements; `health()` and `safe_lookup()` (never-raises wrapper) are already real. |
| `registry.py` | `IdentityRegistry` — register/get/discover, plus `route()`/`route_type()` (folded in; no separate router module). `build_default_registry()` returns an empty registry. |
| `config.py` | `IdentityConfig` (env-driven, mirrors `exposure/config.py`). |
| `cache.py` | `IdentityCache` ABC + `InMemoryIdentityCache` default (interfaces only — no Redis, no persistence). |
| `normalize.py` | Generic payload-parsing helpers (`opt_str`, `str_list`, `parse_iso_datetime`) for a future provider to reuse. |
| `summary.py` | `merge_findings()` — the aggregation function; `merge_assets()` for a future flat-asset view. |
| `service.py` | `IdentityService.investigate(entity) -> IdentitySummary`; `IDENTITY_FRAMEWORK_VERSION`. |
| `providers/` | Empty — a future `HibpProvider`/`EntraIdProvider`/etc. registers here. |

## Provider interface

A future provider implements exactly what TI and Exposure providers already
prove out:

```python
class HibpProvider(IdentityProvider):
    @property
    def metadata(self) -> IdentityProviderMetadata: ...
    async def lookup(self, entity: Entity) -> IdentityFinding: ...   # calls HIBP, delegates to normalize()
    async def normalize(self, raw: Any) -> IdentityFinding: ...      # raw JSON → canonical finding
    async def configuration(self) -> dict[str, Any]: ...             # e.g. {"api_key_configured": True}
```

`health()` and `safe_lookup()` come from the base class unchanged — no
provider reimplements graceful failure.

## Registry design

`IdentityRegistry` combines what TI splits across `ProviderRegistry` +
`ProviderRouter` (and matches `ExposureRegistry`): unique-name registration
(`DuplicateIdentityProviderError` on clash), priority-then-name ordered
discovery, and routing (`route`/`route_type`) that filters on `enabled`,
`supported_entity_types`, and an optional `capability` — pure and synchronous,
no network calls, no global mutable state (tests build isolated registries).
With equal default priority, ordering falls back to the name tiebreak, so
multiple future providers order deterministically with no new logic.

## Canonical model design

`IdentitySummary` is the canonical, frozen output: `findings` (every routed
provider's attribution, successful or not), `references` (deduplicated by URL
across providers), `statistics` (`providers_queried`, `providers_ok`,
`total_findings` — findings that actually carry data, `total_assets`,
`categories`), and `metadata` (entity, timestamp, framework version). The
shape does not change when Phase 6.1 adds real providers — only the values
inside `findings` do. `IdentityAsset` models a discovered artifact (a breached
account, a leaked credential record, a directory account object);
`IdentityEvidence` models a descriptive fact ("appears in Collection #1",
"MFA enrolled: true"). No provider-specific fields anywhere — the models are
provider-agnostic by construction.

## Service design

`IdentityService.investigate(entity)` fans out to every routed provider
concurrently via `asyncio.gather(*p.safe_lookup(entity))` and merges the
results with `merge_findings`. `safe_lookup` guarantees a single buggy
provider can never crash or block a lookup. With zero providers, this returns
a well-formed empty `IdentitySummary` — the real code path, exercised by the
tests, not a stub.

## Testing summary

`backend/tests/identity/` — 75 tests, offline, zero network, zero live
providers, zero API keys: model serialization/classmethods and closed-
vocabulary value pins, the provider ABC's stub/health/`safe_lookup` behavior
via minimal test doubles, registry registration and routing (including
disabled-provider exclusion and capability narrowing), config
defaults/overrides (including `IDENTITY_CACHE_TTL`), the in-memory cache
(including TTL expiry via an injectable fake clock),
`merge_findings`/`merge_assets` aggregation, the service's empty-registry and
fake-provider paths (including a provider whose `lookup` raises, proving
`safe_lookup` never propagates, plus a determinism check), and the
`GET /api/v1/identity` endpoint's exact shape, determinism, and isolation from
the TI path. Full backend suite: **2,201 passed, 1 skipped** (was 2,126
before this phase). Ruff and mypy (strict) clean across 146 source files.
Frontend: **101 tests** (was 98; +3 for the identity client); `npm run build`
clean with the new `/identity` route.

## Performance summary

No network I/O anywhere in this phase — every check is in-memory or a
closed-vocabulary lookup. `GET /api/v1/identity` is a single `len()` call over
an empty registry, synchronous, off the `/investigate` hot path entirely.

## Known limitations (by design in a framework-only phase)

- **Zero providers.** No identity data is retrievable yet; the endpoint and
  page are readiness probes only.
- **Cache/config unwired.** `IdentityCache` and `IdentityConfig` exist as
  contracts but nothing reads them yet — there is nothing to cache or
  configure without a live provider (identical to exposure Phase 5.0).
- **`merge_assets()` is an unused, documented helper** offered for a future
  flat-asset consumer; `merge_findings` keeps assets attached per-provider for
  provenance.
- **No `InvestigationSummary` integration.** Whether/how Identity findings
  join the unified investigation surface is deferred until real provider data
  exists to shape that decision.

## Future provider roadmap (not built — do not begin)

Phase 6.1+ registers concrete providers against this unmodified contract:
Have I Been Pwned (breaches, credential exposure, pastes), Microsoft Entra ID
/ Azure AD, Okta, JumpCloud, Google Workspace, Active Directory, Microsoft
Defender for Identity, CrowdStrike Identity. Each is an `IdentityProvider`
subclass wired into `registry.build_default_registry()` — exactly how
`exposure/providers/` added Shodan/Censys/GreyNoise after Phase 5.0. Every
OAuth2/LDAP/network integration, and any `InvestigationSummary` integration,
is explicitly deferred to those later phases.

## Readiness review

**Readiness: GO.** The framework is a faithful mirror of the twice-proven
Exposure/TI pattern, fully covered by 75 offline tests with zero network
dependency, ruff/mypy-clean, and isolated from every frozen subsystem
(verified: no import crosses into or out of `identity/` except the
`entities/` contract and the single `api/app.py` mount). It is ready to
receive concrete providers in Phase 6.1 with no architectural change — the
same way Exposure's Phase 5.0 framework received Shodan unchanged.
