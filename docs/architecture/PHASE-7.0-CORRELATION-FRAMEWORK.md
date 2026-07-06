# Phase 7.0 — Investigation Correlation Engine Framework

## Status

Complete. Framework only — a pure, deterministic engine plus a **small seed
rule set** (12 rules), no large rule library, no AI, no ML, no scoring
redesign. Opens a new engine the same way the Detection Engine (Phase 4.0)
opened: the full machinery (models, rule model, evaluator, registry, service,
summary, API endpoint, placeholder page) wired end-to-end, with a starter rule
set so the pipeline is exercised. Every prior subsystem — Threat/Knowledge
Intelligence, the Investigation Engine, the frozen Reasoning/Detection/Exposure
Engines, the Detection Knowledge Library, the Operational Dashboard, and the
Identity framework — is untouched.

## Purpose

The Correlation Engine combines a completed investigation's **existing**
findings into higher-level, deterministic *observations* before those richer
observations feed higher-level reasoning:

```
IOC ─▶ Threat Intelligence ─▶ Knowledge ─▶ Exposure ─▶ (Identity, future)
        └────────────── assembled into an InvestigationSummary ──────────────┐
                                                                              ▼
                                                    Correlation Engine (this phase)
                                                                              │
                                                                              ▼
                                            higher-level reasoning / consumers
```

The Reasoning Engine remains solely responsible for findings, confidence,
severity, priority, recommendations, and the investigation summary. The
Correlation Engine adds nothing to those — it only observes that certain
findings *combine* into a recognizable higher-level pattern (e.g. "malicious
infrastructure with exposed services") and references the findings that back
each observation.

### Interface decision (documented)

The spec's pipeline diagram positions correlation conceptually "before"
higher-level reasoning, while the spec's **Engine** section states the concrete
contract explicitly: *Input: `InvestigationSummary`; Output:
`CorrelationSummary`; the engine never mutates `InvestigationSummary`*. This
phase implements that concrete contract. Consuming the assembled
`InvestigationSummary` is the only way to "combine existing evidence" without
inventing any — its `Finding` objects (each wrapping the attributed evidence
the Reasoning Engine assembled) are exactly the existing evidence, and each
observation references them by their stable ids. This mirrors the Detection
Engine, which also consumes `InvestigationSummary`.

## Correlation philosophy (enforced by construction)

- **Never invents evidence.** Every observation is built only from findings
  already present in the input; its `source_finding_ids`, `evidence`, and
  `relationships` reference those findings by id. A test
  (`test_engine.py::TestNeverInventsEvidence`) asserts every referenced id
  exists in the source investigation.
- **Only combines existing evidence.** A rule fires only when the required
  finding categories are already present; it produces a descriptive
  observation, never a new finding, score, confidence, or severity.
- **Fully explainable.** Each observation names the rule that produced it and
  lists the exact findings it combined. Rules are declarative data, not code.
- **No probabilistic inference, no AI, no hidden logic.** One generic
  evaluator interprets declarative rules; output is content-addressed and
  deterministic.

## Architecture decisions

- **Mirrors the Detection Engine (`detection/`), the closest analog.** Both are
  pure, read-only `InvestigationSummary` consumers producing a content-addressed
  package whose identity excludes timestamps. Correlation reuses that exact
  shape: `correlate(summary)` → `CorrelationSummary`, ids hashed over stable
  values, `generated_at` inherited from the source summary.
- **Rules are declarative data, not code.** A `CorrelationRule` is a frozen
  model — `required_categories`, a `same_subject` flag, a `relationship`, a
  `category`, a `title`, a `priority`. A single generic evaluator
  (`engine.evaluate_rule`) interprets every rule, so there is **no per-rule
  code** to test or drift; adding a rule (Phase 7.1) is adding one data object.
- **Two matching modes.** *Same-subject* rules fire once per subject whose
  findings jointly cover every required category (e.g. malicious + exposed on
  one IP). *Cross-subject* rules fire once for the whole investigation when the
  categories co-occur anywhere (e.g. a malware finding and an ATT&CK-technique
  finding on different subjects) — modeling "this investigation surfaced both."
- **Content-addressed, timestamp-independent identity.** An observation id
  hashes rule + category + subject + sorted source finding ids; the summary id
  hashes entity + source engine version + sorted observation ids. Neither
  includes `generated_at`, so re-running correlation on the same investigation
  yields identical ids (verified).
- **Deterministic ordering everywhere.** Rules run in `(priority, id)` order;
  observations are ordered by `(category, subject, id)`; matches by rule id;
  evidence in a stable, de-duplicated order. No randomness, no set iteration
  leaks into output.
- **`CorrelationMatch` references observations by id**, not by value, so the
  per-rule provenance record adds no duplication over the flat `observations`
  list.
- **Framework version starts at `0.1.0`.** Same convention as the Reasoning,
  Detection, and Exposure Engines: it moves to `1.0` only after the rule set is
  expanded and validated end-to-end (Phase 7.1+), never as a bump alone.

## Dependency direction

```
entities/ ,  reasoning/  ←──────  correlation/  (models, rules, registry, engine, summary, service)
```

`correlation/` imports the frozen `reasoning` output contract
(`InvestigationSummary`, `Finding`, `FindingCategory`) and `entities` — exactly
as `detection/` does — and nothing else. `reasoning/` does **not** import
`correlation/` (it is frozen; correlation is strictly downstream). Nothing in
any other subsystem imports from `correlation/`. The one integration point is
`api/app.py`, which mounts `GET /api/v1/correlation` exactly as it mounts every
other subsystem's routes, without threading correlation through `/investigate`.

## Canonical model design

`backend/src/threatlens/correlation/models.py` — closed vocabularies plus
frozen Pydantic value objects:

| Model | Role |
|---|---|
| `CorrelationCategory` | Closed enum of the 12 observation kinds (1:1 with the seed rules). |
| `CorrelationRelationshipType` | Closed enum of how two findings relate (`exposes`, `associated_with`, `mapped_to`, …). |
| `CorrelationRule` | Declarative rule data — `required_categories`, `same_subject`, `relationship`, `category`, `title`, `priority`. |
| `CorrelationEvidence` | A reference to one source finding (id + matched category + subject + copied summary). Never new evidence. |
| `CorrelationRelationship` | A typed link between two source finding ids inside an observation. |
| `CorrelationObservation` | One higher-level observation: content-addressed id, rule id, category, subject, evidence, relationships, source finding ids. |
| `CorrelationMatch` | Per-rule execution record: rule id + the observation ids it produced. |
| `CorrelationStatistics` | `rules_evaluated`, `rules_matched`, `total_observations`, `source_finding_count`, `categories`. |
| `CorrelationMetadata` | Entity, inherited `generated_at`, framework version, source engine version. |
| `CorrelationSummary` | The canonical output: id, entity, observations, matches, statistics, metadata, source finding ids. |

No provider-specific fields; no confidence/severity/priority (those stay in
Reasoning).

## Rule registry design

`CorrelationRegistry` mirrors `DetectionRegistry`: rules keyed by unique id,
`DuplicateCorrelationRuleError` on clash, and a `rules` property ordered by
`(priority, id)` — always stable, no randomness, no plugins.
`build_default_registry()` seeds the 12 rules from `rules.py`; registering more
there is the single wiring point for Phase 7.1's rule expansion, with no engine
change.

## Engine design

`engine.correlate(summary, *, registry=None)` runs each rule (in priority
order) through `evaluate_rule`, collects observations, and delegates to
`summary.build_correlation_summary` for de-duplication, deterministic ordering,
per-rule matches, statistics, the content-addressed summary id, and metadata
(with `generated_at` inherited). `CorrelationService` is a thin wrapper holding
a registry. Pure throughout: no I/O, no AI, no clock, and the input
`InvestigationSummary` is never mutated (verified byte-for-byte).

## Seed rule set (12 rules)

| Rule (category) | Combines | Mode |
|---|---|---|
| `malicious_exposed_infrastructure` | malicious infra + exposure | same subject |
| `vulnerable_exposed_service` | exposure + vulnerability | same subject |
| `known_exploited_vulnerability` | vulnerability + known-exploited | same subject |
| `known_exploited_exposure` | exposure + known-exploited | same subject |
| `reputation_confirmed_infrastructure` | malicious infra + reputation | same subject |
| `misconfigured_exposed_service` | exposure + misconfiguration | same subject |
| `vulnerability_weakness_link` | vulnerability + weakness | same subject |
| `malware_technique_association` | malware + ATT&CK technique | cross subject |
| `actor_technique_mapping` | threat actor + ATT&CK technique | cross subject |
| `actor_malware_association` | threat actor + malware | cross subject |
| `campaign_infrastructure` | campaign + malicious infra | cross subject |
| `malware_infrastructure_association` | malware + malicious infra | cross subject |

Every rule only combines `FindingCategory` values already produced by the
Reasoning Engine. Rule expansion (more rules, richer relationships) is Phase
7.1 — explicitly out of scope here.

## Testing summary

`backend/tests/correlation/` — **79 tests**, offline and deterministic:

- **Models** — serialization round-trips, the ≥2-category rule constraint,
  vocabulary value pins.
- **Rules** — every one of the 12 seed rules fires on its required categories
  and does *not* fire when a category is missing (parametrized).
- **Registry** — registration, duplicate rejection, priority-then-id ordering,
  the 12-rule seed set, 1:1 category mapping.
- **Engine** — empty/single-finding no-match, determinism, content-addressed
  identity, timestamp-independence, read-only (input unmutated), deterministic
  ordering, statistics accuracy, same-subject fan-out and cross-subject
  handling, single multi-category finding (no self-relationship), duplicate
  findings (no duplicate evidence pairs), and the "never invents evidence"
  invariant.
- **Summary** — aggregation, dedup, per-rule matches, summary-id stability.
- **Service** — wraps the engine, seed registry, empty registry, read-only.
- **API** — `GET /api/v1/correlation` exact shape, rule count, determinism, and
  isolation from any TI provider lookup.
- **Golden** — an 18-scenario corpus (each seed rule + empty/single/multi-
  subject/duplicate/multi-category/rich edge cases) snapshotted in
  `golden.json`; CI-gated against drift and regenerated only with
  `THREATLENS_UPDATE_GOLDEN=1`.
- **Perf smoke** — the benchmark harness runs and reports sane shapes.

Full backend suite: **2,280 passed, 1 skipped** (was 2,201). Frontend: **104
tests** (was 101; +3 for the correlation client); build clean with the new
`/correlation` route. Ruff and mypy (strict) clean across 154 source files.

## Performance summary

`tests/correlation/perf.py` — pure, offline, CPU-only. Benchmarks by
**observation count** (each size = N distinct subjects each producing one
observation, from 2N findings). Representative run:

| observations | findings | median | µs / observation | peak alloc |
|---:|---:|---:|---:|---:|
| 10 | 20 | 0.34 ms | 33.8 | 34 KiB |
| 50 | 100 | 1.55 ms | 31.0 | 171 KiB |
| 100 | 200 | 3.15 ms | 31.5 | 357 KiB |
| 500 | 1000 | 16.38 ms | 32.8 | 1.9 MiB |

**Scaling is linear** — per-observation cost varies only **1.09×** across the
range, and peak allocation grows linearly with output size. No bottleneck; **no
optimization was performed** (none is justified — a realistic investigation of a
handful of findings correlates in well under a millisecond).

## Known limitations (by design in a framework-only phase)

- **Seed rules only (12).** A production rule library is Phase 7.1; this set
  demonstrates the engine, not exhaustive coverage.
- **Finding-level references.** An observation references a source `Finding`
  (the natural evidence container), not individual `AttributedEvidence` items
  within it. Deeper drill-down can be added without a contract change.
- **Not integrated into `/investigate`.** The endpoint is a readiness probe;
  wiring `CorrelationSummary` into the investigation response/UI is deferred
  until the rule set is richer (Phase 7.1+).
- **No config/cache layer.** Correlation is a pure CPU transform with no I/O to
  cache or configure, so — unlike the provider frameworks — it ships none.

## Future roadmap (not built — do not begin)

Phase 7.1 expands the rule library against this unchanged engine/registry
contract. Timeline Engine, Graph Engine, Case Management, SOAR, playbooks,
workflow automation, and a MITRE attack graph are all explicitly out of scope
and unstarted.

## Readiness review

**Readiness: GO.** The engine is pure, deterministic, content-addressed,
read-only, and fully covered by 79 offline tests (including a CI-gated golden
snapshot and a linear-scaling perf benchmark), ruff/mypy-clean, and isolated
from every frozen subsystem (verified: it imports only `reasoning`/`entities`
and is imported only by the single `api/app.py` mount). It is ready to receive
an expanded rule set in Phase 7.1 with no architectural change — the same way
the Detection Engine's framework received concrete generators.
