# Phase 4.6 — Detection Knowledge Library (DKL)

## Status

A new subsystem, `threatlens.detection_library`, that discovers, normalizes,
indexes, searches, and **recommends existing community detection content**
(SigmaHQ, YARA-Rules, Emerging Threats, Elastic, Microsoft, Talos, Splunk). It is
strictly **downstream and read-only**: it never generates detections, never
mutates anything, and — critically — **never modifies the frozen Detection Engine
v1.0** (generators, identities, metadata, or API contract are untouched).

The organizing rule of the whole phase: **a Generated Detection and a Community
Detection are different things and are never merged.** ThreatLens *generates*
`DetectionArtifact`s from an investigation (Phase 4.0–4.5, frozen); the DKL
*finds* community `CommunityRule`s that resemble that investigation. They live in
separate packages, separate models, separate API endpoints, and separate UI
sections, each with explicit provenance.

## Generated Detection vs Community Detection

| | **Generated Detection** (Phase 4.0–4.5) | **Community Detection** (Phase 4.6) |
|---|---|---|
| Origin | Produced by ThreatLens from the `InvestigationSummary` | Authored by a third party in a public repository |
| Model | `DetectionArtifact` / `DetectionPackage` | `CommunityRule` / `CommunityRecommendation` |
| Authority | Derives from *this* investigation's findings | Independent; *resembles* the investigation |
| Provenance | Engine version + source finding ids | Repository, author, license, version, URL |
| Endpoint | `POST /api/v1/detections` | `POST /api/v1/detection-knowledge/recommend` |
| UI | "Detection Engineering" card | "Detection Knowledge" card (separate) |
| Mutability | Frozen v1.0 | New, additive; never touches the above |

## Pipeline

```
Community repositories (7 sources)
  └─ Provider (read-only)  · iter_records() → raw record
       └─ normalize_record()  → CommunityRule           (deterministic, offline)
            └─ synchronize()   → LibraryCache            (separate, clock-aware, cacheable)
                 └─ DetectionLibrary (indexed)           (offline; no network on this path)
                      ├─ search(...)         → CommunitySearchResult
                      └─ recommend(summary)  → CommunityRecommendation  (exact/partial/related)
                           └─ API / Frontend "Detection Knowledge"
```

Investigation never triggers a fetch: the library is built once (from the synced
cache when configured, otherwise the bundled seed) and every query is a pure,
in-memory, offline operation.

## Architecture decisions

1. **Modeled on `reference/`, not `detection/`.** The DKL is a bundled-data,
   offline, registry-of-providers subsystem — structurally a sibling of the
   reference-knowledge framework (MITRE/CVE/…), not the generator framework. It
   reuses the frozen `DetectionLanguage` / `DetectionSeverity` /
   `DetectionCategory` vocabularies (community rules are written in the same
   languages ThreatLens generates) and nothing else from `detection/`.
2. **One configurable provider, not seven near-identical files.** A single
   `BundledCommunityProvider` implements the `CommunityProvider` interface from a
   `RuleSource` descriptor + a seed file; the seven sources are *data* in
   `defaults.py`. A future live-fetch provider is a `CommunityProvider` subclass
   overriding `iter_records` — normalize/index/search/match are unchanged. This
   satisfies "future providers plug in without framework changes" without
   duplicated abstractions.
3. **Offline-first, cache-optional.** With no configuration the service reads only
   the bundled seed (stateless, ideal for serverless). A `THREATLENS_DKL_CACHE_DIR`
   opts into a synced cache. Either way the investigation path is offline.
4. **Bundled seed corpus.** Each source ships a small, representative, fully
   attributed seed corpus so the library is functional, testable, and
   deterministic offline. Real network sync is *designed* (the `synchronize` +
   cache framework) but not exercised in CI — no external runtime dependency.
5. **Pure & content-addressed.** `CommunityRule.id` hashes `(source, rule_id,
   content)`, so a rule keeps its id across syncs. `recommend` inherits
   `generated_at` from the summary and reads no clock — identical input yields an
   identical, reproducible result.

## Provider design

`CommunityProvider` (ABC) is **read-only** and declares:

- `metadata → RuleSource` — repository, URL, license, priority, languages;
- `iter_records()` — raw upstream records (offline: from cache/seed);
- `normalize(record) → CommunityRule` — delegates to the shared pipeline;
- `references()` — the repository itself.

`CommunityProviderRegistry` holds providers by unique id in `(priority, id)`
order and exposes `all_rules()`. No provider can reach the Detection Engine.

## Normalization design

`normalize_record(source, record) → CommunityRule` is the "many repositories, one
model" core. It is pure and deterministic, and it does **real parsing** (not just
field copying):

- **Content-addressed id + version** — `com_<sha256[:16]>` over source+rule+body;
  the body fingerprint is the version/change-detection key.
- **ATT&CK extraction** — regex over the rule text (`T1059`, `T1059.001`,
  `attack.t1059.001`), normalized and sorted, unioned with structured hints.
- **IOC extraction** — IPv4 (octet-validated), MD5/SHA1/SHA256, URLs, and domains.
  Domain extraction is deliberately conservative: a bare `a.b` token is an IOC
  only if its last label is a curated public suffix, which rejects rule-DSL
  tokens (`process.name`, `dns.query`, `attack.execution`) and code identifiers;
  vendor/reference hosts (`github.com`, `attack.mitre.org`, …) are dropped so
  documentation links are never mistaken for indicators.
- **Severity / category / platform inference** — from Sigma `level:`/`logsource`
  and language (network languages → NETWORK, YARA → FILE, `product: windows` →
  WINDOWS, …).
- **Provenance** — author, license, version, references, and canonical URL are
  preserved verbatim; the raw body is kept **byte-for-byte** and withheld only
  when the license forbids redistribution.

## Similarity algorithm (deterministic, 0–100)

`score(profile, rule)` is a **fixed weighted sum of per-dimension Jaccard
overlaps** — no embeddings, no LLM, no fuzzy matching. An investigation is
reduced to a `MatchProfile` (IOCs, techniques, malware, actors, categories, tags,
platforms) and each community rule to a parallel `RuleSignature`.

| Dimension | Weight | Source |
|---|---:|---|
| IOC overlap | 38 | finding subjects ↔ rule IOCs |
| MITRE overlap | 24 | relationships ↔ rule techniques |
| Malware family | 12 | relationships ↔ rule families |
| Threat actor | 8 | relationships ↔ rule actors |
| Finding category | 8 | finding categories ↔ mapped rule category |
| Tags | 6 | derived tags ↔ rule tags |
| Platform | 4 | entity-type platform ↔ rule platforms |

`similarity = round(Σ weightᵢ × Jaccard(profileᵢ, ruleᵢ))`, bounded 0–100. The
weights sum to 100 (asserted in tests). **Coverage** is a separate 0–100 metric:
the percent of the investigation's *primary* signals (IOCs + techniques) the rule
addresses.

## Matching algorithm (exact / partial / related)

Classification is driven by **which dimensions overlap**, not merely the
aggregate score, so an exact indicator match is always `EXACT`:

- **EXACT** — shares ≥1 concrete indicator (IOC) with the investigation.
- **PARTIAL** — no shared IOC, but shares a technique, malware family, or actor.
- **RELATED** — only thematic overlap (category / tag / platform) and similarity
  ≥ 8.
- **NONE** — below the floor; never surfaced.

`recommend(summary, library, limit=25)` scores every rule, drops `NONE`, and
ranks by `(match strength, −similarity, −coverage, source priority, source id,
rule id)` — fully deterministic. Every `RuleMatch` embeds the rule (with full
provenance) plus the shared indicators/techniques and a human rationale.

## Caching strategy

Synchronization is **separate from investigation** (`repositories → synchronize →
cache → indexed library → offline search`):

- **`synchronize(registry, now)`** — the only clock-aware / potentially
  network-touching step; snapshots normalized rules + per-source aggregate
  version hashes into a `LibraryCache`. Never called on the investigation path.
- **Incremental updates & version tracking** — `diff(old, new)` reports
  added / content-changed / removed rules by content hash; `source_version` is an
  order-independent aggregate fingerprint per repository.
- **Cache I/O** — atomic `write_cache` / tolerant `read_cache` (returns `None` on
  absent/corrupt/incompatible), `invalidate`, and `is_stale(now, ttl)`.
- **Offline mode** — the service loads the cache when present and fresh, else the
  bundled seed. The investigation never depends on GitHub availability.

## Licensing

Every rule preserves its **repository, author, license, version, and original
URL**; content is never rewritten. `LicenseSupport` governs redistribution of the
*body*:

| Source | License | Support | Body |
|---|---|---|---|
| SigmaHQ | DRL-1.1 | permissive | shown |
| YARA-Rules | GPL-2.0-only | copyleft | shown |
| Emerging Threats | BSD-3-Clause | permissive | shown |
| Microsoft Sentinel | MIT | permissive | shown |
| Splunk | Apache-2.0 | permissive | shown |
| Cisco Talos | GPL-2.0-only | copyleft | shown |
| Elastic | Elastic-2.0 | **restricted** | **withheld** (metadata + link only) |

Elastic's source-available license is treated conservatively: metadata,
attribution, extracted signals, and a link are kept, but the rule body is not
redistributed (a documented `note` explains the choice; reclassify per legal
review). This exercises the "document unsupported licenses" path end-to-end.

## API

Two new read-only endpoints (the Detection Engine's `/detections` is unchanged):

- `POST /api/v1/detection-knowledge/recommend` — body `InvestigationSummary` →
  `CommunityRecommendation` (ranked exact/partial/related matches with
  provenance). Deterministic; never merged with generated detections.
- `GET /api/v1/detection-knowledge/search` — filter by ioc, technique, actor,
  malware, name, tag, rule_id, language, repository, min_severity, platform, text
  (AND-combined) → `CommunitySearchResult` + library stats.

## Frontend

A new **Detection Knowledge** card in the investigation workspace, rendered
*separately* from and below the generated "Detection Engineering" card. It shows
per match: repository, language, similarity, coverage, MITRE, license, author,
last updated, original repository, and View / Download (download only when the
license permits; restricted bodies show a "view at source" notice). Distinct
iconography and copy make clear these are community, not generated, detections.

## Testing summary

Offline, mock/seed-based, no live GitHub. **74 DKL tests** across:

- **Normalization** — extraction primitives, id/version stability, inference,
  license-driven content withholding, determinism.
- **Search** — every axis, AND-combination, pagination, dedup, stats.
- **Similarity** — weights sum to 100, exact/partial/related/none classification,
  coverage, bounds, determinism.
- **Matching** — ranking, provenance, empty investigations, `NONE` never
  surfaced, `generated_at` inheritance, no-merge with generated, determinism.
- **Sync / cache** — snapshot, roundtrip, corrupt-cache tolerance, incremental
  diff, invalidate, staleness, offline fallback, version tracking.
- **Providers** — seven sources, priority order, all languages, read-only,
  duplicate rejection.
- **Licensing** — attribution preserved, per-repo license mapping, redistribution
  respected, restricted body withheld, content never rewritten.
- **API** — both endpoints, separation from `/detections`, enum validation,
  withheld content over the wire.
- **Golden regression** — normalization + matching snapshots (`golden.json`),
  CI-gated against drift.

Backend suite: **1,580 passing** (0 failed, 1 optional-native skip). Frontend:
**39 passing** (+11: `knowledge.test.ts` and community API-client tests). The
Detection Engine v1.0 golden is unchanged.

## Performance summary

Pure, offline (`tests/detection_library/perf.py`). Representative run: build
(normalize 18 rules + index) ≈ 1.6 ms; one search ≈ 0.03 ms; a multi-IOC
recommendation ≈ 0.28 ms. Recommendation **scales linearly** with library size —
per-rule cost varies ≈ 1.1× from 18 → 1000 rules (1000 rules ≈ 14 ms). No
optimization needed.

## Explicit non-goals (respected)

No AI-assisted matching, no embeddings, no live GitHub in CI, no new detection
generators, and **no change to Detection Engineering v1.0**. Exposure Intelligence
is not begun.
