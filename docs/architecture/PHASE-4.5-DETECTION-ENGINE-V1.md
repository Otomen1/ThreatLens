# ThreatLens — Detection Engine v1.0 (Phase 4.5: Validation & Freeze)

## Status

**Frozen at v1.0.** This phase adds **no** new formats, generators, or AI. It
validates the entire Detection Engineering subsystem end-to-end, protects every
generator's output with a byte-stable golden snapshot, benchmarks generation
scaling, reviews the architecture for consistency, and — validation having
succeeded — freezes the engine at `DETECTION_ENGINE_VERSION = "1.0"`.

Like the Reasoning Engine freeze (Phase 3.15), the freeze is a contract: any
future change to generator output must regenerate the golden snapshot, bump the
engine version, and document the change. Nothing downstream of the frozen
`InvestigationSummary` was altered in spirit — the generators are unchanged; only
one Sigma metadata key was added for cross-generator consistency (below).

## 1. What the engine is

The Detection Engine is a **pure, deterministic** consumer of the frozen
`InvestigationSummary`. `detection.generate(summary)` runs every registered
`DetectionGenerator` and returns a `DetectionPackage` of content-addressed
`DetectionArtifact`s. It reads **only** `Finding` objects — never providers, raw
TI, WHOIS, NVD/MITRE JSON, the network, an AI model, or the wall clock.

Nine generators are registered in `build_default_registry()`:

| Kind | Generators (language) |
|---|---|
| Host analytics | Sigma (`sigma`) |
| File | YARA (`yara`) |
| Network IDS/IPS | Suricata (`suricata`), Snort (`snort`) |
| SIEM / EDR queries | Splunk SPL (`splunk_spl`), Sentinel KQL (`sentinel_kql`), Elastic ES\|QL (`elastic_esql`), Chronicle YARA-L (`chronicle_yara_l`), QRadar AQL (`qradar_aql`) |

## 2. Pipeline

```
InvestigationSummary (frozen — the only input)
  └─ detection.generate(summary, *, registry=build_default_registry())
       ├─ for each generator: generator.generate(summary) → artifacts   (pure, independent)
       ├─ _ordered()        → sort by (-severity, language, id)          (deterministic)
       ├─ compute_artifact_id / compute_package_id                        (content-addressed)
       └─ DetectionPackage{ id, metadata, artifacts, languages, references, source_finding_ids }
```

Each generator is independent and additive: it inspects the findings it
understands and emits nothing for the rest. The engine orders and de-duplicates
across all of them. Adding or removing a generator changes only which artifacts
appear — never the identity or content of the others.

## 3. Deterministic guarantees (verified across the corpus)

- **Pure / offline.** No I/O, no AI, no clock. `generated_at` is inherited from
  the summary; the two package/artifact id functions **exclude** it.
- **Timestamp-independent identity.** Re-running a summary with a different
  `generated_at` yields the **same** package id and the **same** artifact ids
  (verified per scenario via `model_copy(update={"generated_at": …})`).
- **Content-addressed.** An artifact id hashes the canonical rule body (plus
  language, target, category, rule id, sorted source finding ids) — so identical
  detections always map to the same `det_…` id, and no two distinct rules collide.
- **De-duplicated.** Multiple findings on one subject (or duplicate findings)
  collapse to one rule per generator; the corpus's `multi_finding_*` and
  `duplicate_*` scenarios assert no duplicate artifact ids.
- **Read-only.** The summary is consumed, never mutated; severity is copied,
  never recomputed.

## 4. Validation corpus

`backend/tests/detection/corpus.py` — **140** deterministic `InvestigationSummary`
scenarios (fixed `NOW`, built parametrically), covering:

| Group | Count | Coverage |
|---|---:|---|
| Supported IOCs × 4 severities × 4 confidence bands + no-ATT&CK | 90 | ipv4, ipv6, domain, url, md5, sha1, sha256, process, registry, powershell |
| Multi-finding (dedup to one rule) | 10 | every supported IOC type |
| Duplicate findings (identical but for id) | 10 | every supported IOC type |
| Conflicting (malicious + informational) | 6 | ip/domain/url/hash subjects |
| Multi-IOC investigations | 5 | ip+hash, domain+url, host triad, mixed, full-spectrum |
| Unsupported subjects (→ no rules) | 11 | cwe, capec, cve, technique, actor, malware family, email, file, api, freetext, unknown |
| Informational-only (→ no rules) | 5 | severity/category floor |
| Malformed hashes | 2 | short MD5, non-hex SHA256 |
| Empty investigation | 1 | no findings |

**17** scenarios expect **no** rules (unsupported / informational / empty); the
other **123** produce **873** artifacts in total. Confidence bands
(low/moderate/high/very-high), severities (low→critical + informational), and
ATT&CK-mapped vs bare findings are all represented. Every one of the nine
generators is exercised (`test_corpus_covers_every_generator`).

## 5. Validation report

`harness.validate_scenario` runs the full generator set on every scenario and
asserts, per artifact:

| Invariant | Check |
|---|---|
| Generation | supported subjects yield rules; unsupported/informational/empty yield none |
| Determinism | `generate(s) == generate(s)` |
| Identity | `det_` prefix, unique ids, id is timestamp-independent |
| Provenance | `metadata.detection_id == artifact.id`, non-empty `finding_ids`, `source_finding_ids ⊆ summary findings` |
| Rule id | every artifact carries a generator `rule_id` |
| ATT&CK | when a technique is mapped, it appears in the rule text |
| Structural validity | parser-level validator for the artifact's language passes |
| Serialization | `DetectionPackage` JSON round-trips byte-for-byte |
| Frontend/API contract | package and artifacts expose the keys the UI consumes |

**Result: 0 violations across all 140 scenarios.** One consistency fix was
required to reach this: the Sigma generator now also emits `detection_id` and
`rule_id` metadata keys (it previously exposed only `sigma_id`), so all nine
generators satisfy `metadata.detection_id == artifact.id`. This adds metadata
keys only; Sigma **rule content is unchanged** (the Phase 4.1 Sigma golden is
byte-identical).

## 6. Native validation (optional, never a CI dependency)

`validate.py` provides parser-level structural validation for all nine languages
(YAML-parse + required Sigma sections; rule/condition + brace balance for YARA
and Chronicle; `alert`/`msg`/`sid`/`rev`/`classtype` + paren balance for
Suricata/Snort; required tokens per SIEM dialect). These validators are unit-
tested directly (`test_validators.py`, 36 cases: valid exemplars, specific
rejection reasons, quote/escape-aware delimiter balancing).

A native layer (`native_available()`, `native_validate_yara()`) compiles rules
with `yara-python`/`pysigma` **only when installed**; the freeze tests skip it
otherwise. **No external validator is bundled or required in CI** — that would
add a runtime dependency. Where native tooling is absent, parser-level validation
applies and this limitation is documented here.

## 7. Performance benchmark

`tests/detection/perf.py` — pure, offline, CPU-only. Generation over
investigations of growing size (distinct-value findings cycled across all IOC
types so every generator fires). Representative run:

| findings | rules | median | µs / rule | peak alloc |
|---:|---:|---:|---:|---:|
| 1 | 8 | 0.42 ms | 52.9 | 35 KiB |
| 10 | 70 | 3.31 ms | 47.3 | 312 KiB |
| 50 | 330 | 15.05 ms | 45.6 | 1.5 MiB |
| 100 | 660 | 31.19 ms | 47.3 | 3.0 MiB |
| 500 | 3290 | 176.2 ms | 53.6 | 15.6 MiB |
| 1000 | 6573 | 382.5 ms | 58.2 | 31.5 MiB |

**Scaling is linear**: per-rule cost varies only **1.28×** across three orders of
magnitude, and peak allocation grows linearly with rule count. **Largest
contributor** (per-generator, at 1000 findings): Chronicle YARA-L (~74 ms), then
the four other SIEM generators (~36–40 ms each), Sigma (~31 ms), Snort/Suricata
(~19–20 ms), YARA (~6 ms). No bottleneck warrants optimization — generation of a
realistic investigation (single-digit findings) completes in well under a
millisecond. **No optimization was performed** (none is justified).

## 8. Golden regression

`tests/detection/golden.json` snapshots every scenario × every generator:
package id, languages, source finding ids, and per-artifact `{id, language,
category, severity, rule_id, validation status, finding_ids, attack, content
sha256[:16]}`. `test_golden_regression` fails on any drift and names the drifted
scenarios. Regeneration is deliberate and gated:

```
THREATLENS_UPDATE_GOLDEN=1 pytest tests/detection/test_detection_freeze.py::test_golden_regression
```

The CI **golden-regression job** now runs `tests/detection` alongside the
reasoning benchmark and IOC-validation goldens, so any unintended change to any
generator's output turns CI red until the golden is intentionally regenerated and
the engine version is bumped.

## 9. Architecture review

The subsystem is internally consistent and matches Phase 0 / 4.0:

- **Single input, single direction.** Every generator consumes only `Finding`s;
  nothing reads back into Investigation / Reasoning. The Detection Engine remains
  a terminal downstream consumer of the frozen `InvestigationSummary`.
- **Shared helpers, no duplication.** Network generators share `_netrules.py`;
  the five SIEM generators share `_siemcommon.py`; all reuse the framework's
  models, `TemplateRegistry`, and `compute_artifact_id`. No generator
  re-implements identity, ordering, or de-duplication — the engine owns those.
- **Additive registry.** `build_default_registry()` lazily imports each generator
  (no engine↔generator cycle); the engine and `POST /api/v1/detections` are
  unchanged as generators are added.
- **Identity is the rule body.** Timestamps and any future AI annotation are
  excluded from every id, preserving package-id stability.

## 10. Public API contract — `POST /api/v1/detections`

Unchanged by this phase. Body: an `InvestigationSummary`. Response: a
`DetectionPackage` `{id, metadata, artifacts[], languages[], references[],
source_finding_ids[]}`; each artifact carries `{id, language, target, title,
content, severity, category, rule_id, validation, metadata, references,
source_finding_ids}`. Unsupported/informational/empty investigations return a
well-formed package with `artifacts: []` (never an error). The serialization
round-trip and the frontend key contract are asserted for every corpus scenario.

## 11. Testing summary

- **Backend total: 1507 tests — 1506 passed, 1 skipped, 0 failed.**
  (The single skip is native YARA validation, absent by design in CI.)
- **Detection freeze suite: 184 tests** — 140 per-scenario invariant checks, the
  corpus-shape/coverage/freeze-marker checks, golden regression, 36 validator
  unit tests, and 3 perf-harness smoke tests.
- **No regressions.** Six stale exact-equality assertions from Phases 4.2–4.4
  (e.g. `registry.languages == (SIGMA,)`, `pkg["languages"] == ["sigma"]`,
  `artifacts[0]`) were updated to membership / by-language selection now that the
  registry holds nine generators. These were product-correct all along; the
  assertions had simply not been updated as generators were added.
- Frontend build + tests remain green (no frontend change in this phase).
- Golden snapshots (reasoning, IOC validation, and all generator content) remain
  byte-stable.

## 12. Freeze checklist

- [x] Corpus of 140 scenarios covering every subject, severity, band, ATT&CK
      state, multi/duplicate/conflicting/unsupported/malformed/empty case, and
      every generator.
- [x] Per-scenario invariants (generation, determinism, identity, provenance,
      ATT&CK, validity, serialization, contract) — 0 violations.
- [x] Parser-level validation for all nine languages + optional native layer,
      unit-tested; CI dependency-free.
- [x] Golden snapshot for every generator × scenario; CI-gated against drift.
- [x] Performance benchmarked at 1–1000 findings; linear; no optimization needed.
- [x] Architecture reviewed for consistency; no cross-layer leakage.
- [x] Backend suite ≥ 1500 tests, green; frontend green; goldens unchanged.
- [x] `DETECTION_ENGINE_VERSION = "1.0"`.

## 13. Remaining weaknesses (honest)

- **Parser-level, not semantic.** Absent native toolchains in CI, validation
  confirms structure, not that (e.g.) a Splunk query returns the intended events.
  Native validation is wired but optional.
- **Malformed inputs pass through descriptively.** A malformed hash still yields a
  Sigma tag (hash-validating generators skip it); this is deliberate and covered,
  but the engine trusts the upstream normaliser for value correctness.
- **Fan-out cost is dominated by the SIEM generators.** They fire for every IOC
  type, so a very large investigation's cost is ~5× a single-language engine.
  This is linear and small in absolute terms; noted for future SIEM tuning.

## 14. Freeze recommendation

**Readiness: 9.5 / 10. Recommendation: GO — freeze Detection Engineering at
v1.0.** The subsystem is pure, deterministic, content-addressed, fully covered by
a 140-scenario corpus with zero invariant violations, protected by a CI-gated
golden snapshot for all nine generators, validated structurally (with an optional
native layer), and benchmarked as linear with no bottleneck. The half-point
reserved reflects the parser-level (vs universally-native) validation ceiling,
which is documented and mitigated. Future generator changes follow the same
contract as the Reasoning Engine freeze: regenerate the golden, bump the version,
document the change.
