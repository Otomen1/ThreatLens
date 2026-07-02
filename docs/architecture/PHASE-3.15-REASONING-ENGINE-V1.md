# ThreatLens — Reasoning Engine v1.0 (Phase 3.15: Validation & Freeze)

**Status:** Frozen reference architecture. `ENGINE_VERSION = "1.0"`.
**Scope of this phase:** validate, benchmark, calibrate, and freeze the existing
deterministic reasoning engine. **No new features.** The only production change
is the version stamp (`3.1d → 1.0`) marking the freeze.

This document is the reference architecture for the engine that AI (Phase 3.2),
Detection Engineering, Report Parsing, and Exposure Intelligence will depend on.
It records what the engine guarantees, how it was validated, the calibration /
rule / recommendation reviews, measured performance, the public API contract,
and the freeze checklist.

---

## 1. What the engine is

The reasoning engine turns aggregated intelligence about **one entity** into a
deterministic **`InvestigationSummary`** — posture, overall confidence, findings,
and recommendations — with full per-factor explainability and no AI.

Its entire public surface is one pure function:

```python
reason(
    entity: Entity,
    ti: AggregatedResult,            # external threat-intelligence (may be empty)
    knowledge: AggregatedResult,     # reference knowledge: MITRE/NVD/CWE/CAPEC (may be empty)
    *,
    context: InvestigationContext = EMPTY_CONTEXT,   # optional; affects priority only
    now: datetime | None = None,     # injected clock for deterministic freshness
) -> InvestigationSummary
```

For identical inputs (including `context` and `now`) the output is **byte-for-byte
identical**. The function never touches the network, never calls an LLM, and
holds no mutable state.

---

## 2. Pipeline

```
reason(entity, ti, knowledge, context, now)
  │
  ├─▶ EvidenceAssembler.assemble(ti, knowledge, now)
  │     normalize attributed evidence + lift provider reputations into a
  │     weighted ledger (weight = base_weight × authority × freshness);
  │     assign each item a polarity + dimension. No scoring, no findings.
  │
  ├─▶ FindingEngine.generate(entity, ledger, now)
  │     run every rule's predicate/effect → drafts;
  │     merge drafts by (subject_type, subject_value, primary_category);
  │     score each finding with ConfidenceScorer; assign a content-addressed id;
  │     sort worst-first (severity ↓, confidence ↓, id).
  │
  ├─▶ derive_finding_priority(severity, confidence, context)   # per finding
  │     severity_base = (4 − severity) × 100
  │     confidence_penalty = (4 − band_rank) × 10
  │     priority = max(0, severity_base + confidence_penalty − context_boost)
  │
  ├─▶ RecommendationEngine.for_finding(finding)                # finding-owned
  │     gate by category/severity/confidence → actions;
  │     recommendation priority = finding.priority + action_rank.
  │
  └─▶ assemble InvestigationSummary
        posture        = worst finding severity
        overall_conf   = headline (worst) finding's confidence
                         (or the evidence-level confidence when no finding fired)
        recommendations = RecommendationEngine.rollup(findings)
                         (dedupe + merge across findings, conflict-resolve,
                          priority-order, retain finding_ids provenance)
```

### Module responsibilities (single-purpose, dependency flows one way)

| Module | Responsibility | Pure | Network | AI |
|---|---|---|---|---|
| `reasoning/config.py` | Static knobs: authority map + families, evidence base weights/dimensions/polarity, reputation lift, freshness decay | data | no | no |
| `reasoning/evidence.py` | `EvidenceAssembler` — normalize TI+knowledge → weighted ledger | ✓ | no | no |
| `reasoning/confidence.py` | `ConfidenceScorer` — 4-factor score + band + explanation | ✓ | no | no |
| `reasoning/rules.py` | 5 typed finding rules (predicate/effect) | ✓ | no | no |
| `reasoning/findings.py` | `FindingEngine` — draft → merge → score → identity | ✓ | no | no |
| `reasoning/priority.py` | `derive_finding_priority` — the single urgency formula | ✓ | no | no |
| `reasoning/recommendations.py` | 5 recommendation rules + dedupe/merge/conflict/rollup | ✓ | no | no |
| `reasoning/registry.py` | Finding-rule registry (id-sorted, deterministic order) | ✓ | no | no |
| `reasoning/engine.py` | `reason()` — composes the pipeline | ✓ | no | no |
| `reasoning/models.py` | Frozen canonical models + enums | — | no | no |

---

## 3. Deterministic guarantees

1. **Pure & reproducible.** No globals, no I/O, no AI. `now` is injected, so
   freshness — the only time-dependent factor — is deterministic in tests and CI.
2. **Stable finding identity.** A finding id is
   `fnd_` + `sha256(primary_category | subject_type | subject_value | sorted canonical
   evidence "type:value")[:16]`. It excludes timestamps, free-text wording,
   ordering, and AI. The same evidence always yields the same id (pinned in the
   benchmark golden snapshot and by an explicit id assertion).
3. **Stable recommendation ordering.** Priority is one formula
   (`finding.priority + action_rank`); the rollup is sorted by
   `(priority, action, target)`. No second priority algorithm exists.
4. **Provider-independent.** The engine consumes the shared `AggregatedResult`
   contract; it has no provider-specific code. Authority/family is data in
   `config.py`; an unknown provider gets a modest default (0.4).
5. **Context-safe.** `InvestigationContext` influences **priority only** (a
   uniform, non-negative shift). It never changes evidence, confidence, severity,
   finding generation, or recommendation generation. The default
   `EMPTY_CONTEXT` reproduces context-free behaviour exactly.
6. **AI-independent.** AI is strictly downstream and is not imported anywhere in
   the package (see §8).

---

## 4. Confidence calibration review

Confidence is a weighted sum of four factors (weights are the approved
architecture set and sum to 1.0):

| Factor | Weight | Meaning |
|---|---|---|
| **Authority** | 0.35 | Max authority among supporting sources (`nvd` 0.95 · `mitre_attack`/`cwe` 0.90 · `capec` 0.85 · `urlhaus`/`malwarebazaar` 0.70 · `abuseipdb`/`otx` 0.60 · default 0.40) |
| **Agreement** | 0.25 | Supporting weight ÷ (supporting + contradicting) |
| **Corroboration** | 0.25 | `1 − 1/len(families)` — counts independent authority **families**, not raw provider count |
| **Freshness** | 0.15 | Recency of the freshest supporting item; full ≤ 30 d, floor 0.3 ≥ 1 y, undated = 1.0 |

Bands: `< 10` INSUFFICIENT · `< 30` LOW · `< 60` MODERATE · `< 85` HIGH · `≥ 85`
VERY_HIGH. A **contested** finding (contradiction share ≥ 0.25) is capped at
MODERATE unless carried by an authoritative fact (authority ≥ 0.90).

### Emergent properties verified against the benchmark

These were validated by hand and pinned by the regression corpus (golden values
cited):

- **Corroboration is the lever between HIGH and VERY_HIGH.** A single
  uncontradicted source can reach HIGH (agreement contributes a flat 0.25 and
  freshness up to 0.15), but **VERY_HIGH is unreachable without ≥ 2 independent
  families.** Example: `cve_critical` (NVD only) = **73 / HIGH**; the same CVE
  also seen in OTX (`cve_critical_corroborated`, two families) = **86 / VERY_HIGH**.
- **Community TI reputation caps at ~HIGH.** With max TI authority 0.70 and at
  most three TI families, the ceiling is ≈ 81. VERY_HIGH is therefore reserved
  for authoritative-knowledge corroboration (NVD/MITRE), which is the intuitive
  outcome — community feeds should not, alone, produce "very high" certainty.
  (`malware_very_high` reaches **88 / VERY_HIGH** only by combining abuse.ch +
  OTX + MITRE.)
- **The echo-chamber guard works.** `urlhaus` + `malwarebazaar` collapse into the
  single `abuse.ch` family, so `hash_echo_chamber` scores the same band as a
  single abuse.ch source — mirrored feeds cannot manufacture corroboration.
- **Contested findings are capped.** `ip_contested` (malicious + benign) =
  **50 / MODERATE, contested** even though severity is HIGH.
- **Confidence gates action.** `ip_low_confidence_refuted` (a weak, stale,
  refuted detection) = **22 / LOW** and produces **zero recommendations** — the
  recommendation gate (min MODERATE) correctly suppresses action on weak findings.

### Verdict

The factor weights are the approved architecture set; this review **confirms they
produce intuitive, defensible results** across the full corpus and makes **no
changes**. The single-source "floor" (an uncontradicted authoritative fact
reaching HIGH) is intentional — absence of contradiction is genuine signal, and
VERY_HIGH remains gated behind real corroboration. One documented nuance: a
provider *reputation verdict* is lifted as undated evidence (freshness 1.0), so a
verdict never ages on its own — only dated evidence (detections, sightings)
decays. This is deliberate (the verdict is the provider's current position) and
is exercised by `ip_reputation_timeless_over_stale_detection`.

---

## 5. Finding rule review

Five typed rules; each is pure, type-checked, unit-tested, and evaluated in a
deterministic id-sorted order. Drafts merge by `(subject_type, subject_value,
primary_category)` taking the max severity and the union of evidence/categories.

| Rule | Fires on | Severity | Notes |
|---|---|---|---|
| `vuln.critical` | CVE with NVD severity HIGH/CRITICAL | HIGH / CRITICAL | The only rule whose severity is data-derived. Recasts the CVE record as supporting evidence for itself (intentional — the authoritative record corroborates the finding). |
| `infra.malicious` | IP/IPv6/domain/URL with supporting reputation-dimension evidence | HIGH | Fires on SUSPICIOUS as well as MALICIOUS; severity is uniform HIGH and the **nuance lives in confidence**, not severity. |
| `malware.known` | malware-family evidence/relationship, or a malware-family entity | HIGH | May co-fire with `infra.malicious` on a malicious URL → two findings whose `BLOCK` recommendations merge in the rollup. |
| `actor.attributed` | a threat-actor entity, or an `ATTRIBUTED_TO` actor relationship | MEDIUM | Only `ATTRIBUTED_TO` triggers via relationship; MITRE's weaker `ASSOCIATED_WITH` does **not** — this deliberately avoids over-attribution. |
| `attack.technique` | a technique entity, or any `ATTACK_PATTERN` relationship | MEDIUM | Surfaces ATT&CK linkage for techniques, CWE, and CAPEC. |

**Quality assessment.** Rules are deterministic and understandable; categories do
not duplicate one another (each owns a distinct `FindingCategory`); legitimate
co-firing (e.g. infra + malware on a URL) is handled by the merge + recommendation
rollup, not by overlap in a single category. Edge cases are covered by the
benchmark (benign-only, contextual-only, tag-only, contested, stale, sparse,
unknown).

**Documented minor weaknesses (no change pre-freeze):**

- `attack.technique` titles a CWE/CAPEC finding "Observed attack technique:
  CWE-79". The ATT&CK linkage it surfaces is correct, but the noun is loose — a
  CWE is a *weakness related to* attack patterns, not an *observed technique*. A
  wording refinement is a candidate for a future minor revision; it is **not**
  changed now because the output is frozen and the imprecision is cosmetic.
- Rule severities are fixed (except `vuln.critical`). This is a deliberate
  simplicity: severity is coarse and **confidence + priority carry the nuance**.

No new rules added (per scope). No rule changed.

---

## 6. Recommendation rule review

Five recommendation rules map a finding category to SOC-sensible actions. They
read **only findings** — never providers, aggregated evidence, raw reputation, or
API responses.

| Finding | Actions | Would a SOC analyst agree? |
|---|---|---|
| Critical vulnerability | `PATCH_IMMEDIATELY` + `INVESTIGATE` (verify exposure) | Yes |
| Malicious infrastructure | `BLOCK` + `THREAT_HUNT` | Yes |
| Known malware | `BLOCK` (isolate host) + `INVESTIGATE` (scan host) | Yes |
| Threat actor | `INVESTIGATE` (related IOCs) + `ENRICH` (history) | Yes |
| Attack technique | `THREAT_HUNT` + `GENERATE_DETECTION` (review coverage) | Yes |

**Determinism & ordering.** Recommendation priority inherits the finding priority
plus a fixed per-action rank; the rollup is sorted by `(priority, action, target)`.
Ordering is stable and pinned by the benchmark and the API-contract test.

**Dedupe / merge / conflict.**
- Within a finding, identical `(action, target)` recommendations are de-duplicated
  (most-urgent wins).
- Across findings, identical `(action, target)` are merged with `finding_ids`
  unioned — demonstrated by `url_malicious_urlhaus`, where the infra and malware
  findings both emit `BLOCK` and collapse to a single rollup row citing both.
- Conflict policy `_SUPERSEDES` lets `BLOCK`/`PATCH_IMMEDIATELY` supersede
  `MONITOR` on the same target. **Observation:** no current rule emits `MONITOR`,
  so this policy is **latent/forward-compatible**, not dead-by-mistake. Left
  in place; documented.

**Gating.** Every rule requires at least MODERATE confidence, so LOW/INSUFFICIENT
findings produce no actions (verified). Actions are additive and never
contradictory (no "block" vs "allow"). No new recommendations added; none changed.

---

## 7. Performance benchmark

Measured offline, CPU-only, on a representative heavy input (a malicious IP that
drops malware, is attributed to an actor, and uses a technique → **four
findings**). Per-call latency (median of 2000 iterations; this environment):

| Stage | Median | p95 |
|---|---:|---:|
| Entity detection | 24.5 µs | 40.2 µs |
| Provider routing (TI) | 41.9 µs | 66.3 µs |
| Provider routing (reference) | 8.1 µs | 11.0 µs |
| Aggregation | 15.1 µs | 22.7 µs |
| Evidence assembly | 18.1 µs | 27.6 µs |
| Confidence scoring | 15.3 µs | 25.5 µs |
| Finding generation | 192.1 µs | 246.1 µs |
| Recommendation rollup | 0.9 µs | 1.0 µs |
| **End-to-end `reason()`** | **357 µs** | **415 µs** |

The full deterministic investigation runs in **well under a millisecond**.
Finding generation dominates (it runs all rules, merges, and scores each group),
which is expected and still trivially cheap. **No bottleneck exists; no
optimization was performed.** Outbound provider I/O is network-bound and out of
scope here — it is the real latency budget for a live investigation and is
handled at the provider layer (timeouts, concurrency, caching), not in the
deterministic core.

Reproduce with `python tests/benchmark/perf.py`; a smoke test keeps the harness
exercised in CI without timing assertions (which would flake on shared runners).

---

## 8. The AI boundary

The engine is the **deterministic source of truth**. AI (Phase 3.2) will be a
strictly downstream, read-only consumer of the immutable `InvestigationSummary`.

- AI **must not** write back into findings, severity, confidence scores,
  priorities, or recommendations — those remain 100% deterministic.
- AI may produce a grounded natural-language narrative whose every claim cites a
  finding/evidence id already present in the summary; it adds no new facts.
- All provider-derived text is attacker-controllable and must enter any future
  prompt as clearly delimited untrusted data.
- Today the `reasoning` package imports no AI and has no AI seam — AI sits
  *above* `reason()`, consuming its output. This boundary is a freeze invariant.

---

## 9. Public API contract — `POST /api/v1/investigate`

Treated as a public, frozen API. The response is additive-only: new optional
fields may be introduced, but documented fields are never removed or retyped.

```
InvestigationResponse
├─ investigation_id: UUID
├─ entity: Entity
├─ threat_intelligence: AggregatedResult
├─ knowledge: AggregatedResult
└─ investigation_summary: InvestigationSummary
   ├─ entity_type, entity_value
   ├─ posture: int            # Severity 0..4 serialized as int
   ├─ overall_confidence: Confidence {score:int, band:str, contested:bool, factors:[{name,contribution,detail}]}
   ├─ categories: [str]
   ├─ findings: [Finding {id, title, categories:[str], subject_type, subject_value,
   │             severity:int, confidence:Confidence, priority:int,
   │             evidence:[WeightedEvidence {evidence:{evidence,sources}, weight, polarity, dimension}],
   │             relationships:[...], sources:[str], rationale, rule_ids:[str],
   │             recommendations:[Recommendation]}]
   ├─ recommendations: [Recommendation {action, category, priority:int,
   │             target_type, target_value, rationale, rule_id, finding_ids:[str]}]   # priority-ordered rollup
   ├─ engine_version: "1.0"
   └─ generated_at: datetime
```

**Backwards compatibility & stability** are enforced by `tests/test_api_contract.py`
(subset assertions on every level + scalar-type checks + rollup-ordering +
OpenAPI component presence). `/detect` and the pre-existing AggregatedResult keys
are pinned too. The frozen `engine_version` lets downstream consumers detect any
deliberate future change to engine output.

---

## 10. Regression benchmark

**`backend/tests/benchmark/`** — a deterministic, offline corpus that pins the
`reason()` input → output contract and runs as part of CI.

- **58 scenarios** (target 50–100), each constructed from synthetic
  `AggregatedResult` inputs that mirror exactly what real providers emit
  (`EvidenceType` / `RelationshipTargetType` / `ReputationLevel` combinations).
- **Coverage:** benign/malicious/suspicious/likely-malicious IPv4 & IPv6;
  benign/malicious domains & URLs; blocklist; MD5/SHA1/SHA256 malware; unknown &
  sandbox-only hashes; critical/high/medium/low CVE (+ corroborated → VERY_HIGH);
  ATT&CK technique & sub-technique; threat actor (with/without technique links);
  malware family (incl. VERY_HIGH); CWE; CAPEC; multi-finding (IP and domain);
  conflicting/contested; sparse; stale vs fresh; echo-chamber vs independent
  corroboration; full context matrix (criticality, environment, internet-facing,
  no-op dev) and the uniform-priority-shift property; empty/freetext/unknown.
- **Three checks per scenario:** declarative expectations (posture, overall
  band/contested, per-finding category/severity/confidence/priority, ordered
  recommendation actions), determinism (identical across two calls), and
  content-addressed identity.
- **Golden snapshot** (`golden.json`) pins every output field
  (findings/severity/confidence/recommendations/priority/ids) byte-for-byte — the
  exhaustive drift guard. Regenerate deliberately with
  `THREATLENS_UPDATE_GOLDEN=1 pytest`.

**Regression strategy.** Any unintended change to engine output fails CI: the
declarative tests catch intent regressions with readable messages; the golden
snapshot catches *any* numeric/id/ordering drift. A deliberate change requires
regenerating the golden file and bumping `ENGINE_VERSION` — making engine
evolution explicit and reviewable before downstream features depend on it.

---

## 11. Freeze checklist

| Guarantee | Status | Evidence |
|---|:--:|---|
| **Deterministic** | ✓ | `now` injected; `test_scenario_is_deterministic` over all 58 scenarios |
| **Explainable** | ✓ | every `Confidence` carries 4 signed factors; findings carry rule_ids + rationale + cited evidence |
| **Testable** | ✓ | 829 backend tests; offline; benchmark + golden in CI |
| **Pure** | ✓ | no globals/I/O/AI; functional pipeline; frozen Pydantic models |
| **Provider-independent** | ✓ | consumes shared `AggregatedResult`; authority/family is data; unknown → default |
| **AI-independent** | ✓ | no AI import in `reasoning/`; AI consumes output downstream only (§8) |
| **Context-safe** | ✓ | context affects priority only; `EMPTY_CONTEXT` == context-free; `test_investigation_context` + benchmark context matrix |
| **Stable Finding IDs** | ✓ | content-addressed sha256; pinned id assertion + golden |
| **Stable Recommendation ordering** | ✓ | one priority formula; rollup sorted `(priority, action, target)`; benchmark + contract |
| **Stable API** | ✓ | additive-only; `test_api_contract.py` + OpenAPI components; `engine_version = "1.0"` |

---

## 12. Remaining weaknesses

None are correctness defects; all are low-impact with clear rationale.

1. **`attack.technique` wording for CWE/CAPEC** — the finding title says "Observed
   attack technique" for entities that *relate to* (rather than exhibit) a
   technique. Cosmetic; candidate for a future minor revision.
2. **Fixed rule severities** (except `vuln.critical`) — coarse by design;
   confidence and priority carry the nuance.
3. **No-finding fallback confidence** — when no rule fires, `overall_confidence`
   echoes raw evidence strength, so a high-confidence-but-not-a-finding state can
   show (e.g. a sandbox observation with no family → MODERATE confidence,
   INFORMATIONAL posture). Posture is the headline; minor UX note.
4. **Latent `_SUPERSEDES` MONITOR policy** — inactive until a rule emits `MONITOR`.
   Forward-compatible, not a bug.
5. **Reputation verdicts are timeless** — only dated evidence decays. Deliberate.

---

## 13. Freeze recommendation

**Yes — release as Reasoning Engine v1.0.**

The engine is deterministic, pure, explainable, provider- and AI-independent, and
context-safe. Its behaviour is now pinned by a 58-scenario regression corpus plus
a byte-level golden snapshot, validated by 829 passing tests, clean Ruff and
strict mypy, and a sub-millisecond performance profile with no bottleneck. The
calibration, rule, and recommendation reviews confirm intuitive, SOC-defensible
output and surfaced only minor, documented, non-blocking weaknesses — none
requiring a pre-freeze code change. The public `/investigate` contract is pinned
and additive-only.

Freezing now gives AI, Detection Engineering, Report Parsing, and Exposure
Intelligence a stable, trustworthy foundation: any future change to engine output
must regenerate the golden snapshot and bump `ENGINE_VERSION`, making evolution
explicit and reviewable. The engine is ready to freeze at **v1.0**.
