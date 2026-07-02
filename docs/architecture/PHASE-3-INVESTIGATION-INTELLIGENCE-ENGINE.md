# ThreatLens — Phase 3: Investigation Intelligence Engine (Final Approved Specification)

> Status: **approved with minor changes** (independent architecture review, Phase 3.0.1).
> This is the specification Phase 3.1 implementation begins from.
> Design-only document — no production code, tests, or APIs are changed by it.

---

## 0. Thesis & placement

The Investigation Intelligence Engine is a **pure, deterministic reasoning stage** inserted *after* aggregation and *before* AI. It turns aggregated intelligence into **Findings**.

```
detect → route → providers → aggregate ─►  REASONING ENGINE  ─► InvestigationSummary ─► (AI) ─► (Detection Eng.)
                              (existing)     (new, Phase 3.x)        (new contract)      read-only consumers
```

Public contract — one pure function, mirroring `aggregate()`:

```
reason(entity: Entity,
       ti: AggregatedResult,
       knowledge: AggregatedResult,
       *, context: InvestigationContext = EMPTY,
          config: ReasoningConfig) -> InvestigationSummary
```

No network, no AI, no mutation of inputs; synchronous and reproducible — the same purity contract as detection and aggregation. Lives in a new package `threatlens.reasoning`. The `InvestigationService` gains one step after `aggregate`; the `/investigate` response gains one **additive** field (`investigation_summary`). **The Provider, Reference, Aggregation, and Investigation frameworks are unchanged.**

---

## 1. Component diagram

```
                         ┌──────────────────────── threatlens.reasoning ────────────────────────┐
 AggregatedResult (TI)   │                                                                       │
 AggregatedResult (KB) ──┼─► EvidenceAssembler ─► Correlator ─► RuleEngine ─► ConfidenceScorer ─►│─► InvestigationSummary
 Entity ─────────────────┤        │                  │            │   ▲            │             │        │
 InvestigationContext ───┤        ▼                  ▼            ▼   │            ▼             │        ▼
   (optional, EMPTY)     │   EvidenceLedger     evidence groups  Finding rules  Confidence    Recommender│   (read-only)
                         │   (WeightedEvidence) (per dimension)  + categories   (4 factors)   (rec. rules)│  AI / Detection /
                         │        ▲                                  ▲                          ▲         │  Timeline / Case /
                         │   AuthorityMap   EvidenceWeightTable   RuleRegistry           RecommendationRules  Graph
                         └──────────────────────────────────────────────────────────────────────────┘
                   context affects ── Priority + Recommendations only (never Severity/Confidence/Evidence)
```

Every box is pure and independently testable; every config block (AuthorityMap, EvidenceWeightTable, RuleRegistry, RecommendationRules) is versioned data, matching the "registry of small units" idiom (detectors, providers).

---

## 2. Data-flow / lifecycle

```
Search → Detect → Collect → Normalize → Aggregate → (ti, knowledge)          ── existing
 ┌──────────────────────────── REASONING (new, pure) ─────────────────────────┐
 │ 1 Assemble   AttributedEvidence + Reputation + Relationships → WeightedEvidence (ledger)
 │ 2 Correlate  group by (subject, dimension); detect agreement vs contradiction
 │ 3 Evaluate   RuleEngine over ledger → Findings (+categories, +severity); deterministic merge
 │ 4 Score      ConfidenceScorer per finding (4 factors → score → band, contested?)
 │ 5 Recommend  per-finding RecommendationRules → Recommendations (finding-owned)
 │ 6 Prioritize derive Priority per finding from (severity, confidence, InvestigationContext)
 │ 7 Assemble   InvestigationSummary (posture, findings, recommendation rollup, provenance)
 └─────────────────────────────────────────────────────────────────────────────┘
        → AI Summary (read-only, grounded, cited) → Detection / Timeline / Case / Graph (consume findings)
```

Steps 1–7 are deterministic and offline. Everything after consumes the immutable summary and never writes back.

---

## 3. Canonical models (design sketches — NOT for implementation)

Reuse existing `Entity`, `EntityType`, `Evidence`, `AttributedEvidence`, `Relationship`, `AttributedRelationship`, `Reputation`. New models *reference* them.

```python
# ---- enums ----
class Severity(IntEnum):            # how bad IF true — ordinal, comparable
    INFORMATIONAL=0; LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4

class ConfidenceBand(StrEnum):
    INSUFFICIENT; LOW; MODERATE; HIGH; VERY_HIGH

class EvidencePolarity(StrEnum):
    SUPPORTING; CONTRADICTING; CONTEXTUAL

class EvidenceDimension(StrEnum):   # closed set (see §7) — replaces free-text dimension
    REPUTATION; EXPLOITATION; EXPOSURE; ATTRIBUTION; WEAKNESS; CAPABILITY; INFRASTRUCTURE

class FindingCategory(StrEnum):     # closed, extensible; a finding holds a SET
    MALICIOUS_INFRASTRUCTURE; VULNERABILITY; WEAKNESS; ATTACK_PATTERN
    THREAT_ACTOR; MALWARE; CAMPAIGN; EXPOSURE; MISCONFIGURATION; REPUTATION
    KNOWN_EXPLOITED; HIGH_PRIORITY; ACTION_REQUIRED; CONTESTED; INFORMATIONAL

class RecommendationCategory(StrEnum):   # closed — do not expand
    CONTAINMENT; INVESTIGATION; REMEDIATION; FORENSICS

class RecommendationAction(StrEnum):
    PATCH_IMMEDIATELY; MONITOR; BLOCK; INVESTIGATE; THREAT_HUNT
    GENERATE_DETECTION; COLLECT_MEMORY; ACQUIRE_DISK; ENRICH; ESCALATE; NO_ACTION_NEEDED

# ---- investigation context (optional engine input; see §5) ----
class AssetCriticality(StrEnum):
    UNKNOWN; LOW; MEDIUM; HIGH; CRITICAL

class Environment(StrEnum):
    UNKNOWN; DEVELOPMENT; STAGING; PRODUCTION

class InvestigationContext(frozen):       # default = EMPTY (all unknown / false / empty)
    criticality: AssetCriticality = UNKNOWN
    environment: Environment = UNKNOWN
    internet_facing: bool = False
    tags: list[str] = []
    attributes: dict[str, str] = {}        # hostname, business_unit, customer, … (un-modeled)

# ---- derived evidence (wraps existing AttributedEvidence; does NOT replace it) ----
class WeightedEvidence(frozen):
    evidence: AttributedEvidence            # reuse — keeps .evidence + .sources
    weight: float                           # 0..1, deterministic
    polarity: EvidencePolarity
    dimension: EvidenceDimension            # closed enum

# ---- confidence ----
class ConfidenceFactor(frozen):
    name: str                               # authority|agreement|corroboration|freshness
    contribution: int                       # signed points added to the score
    detail: str                             # deterministic, human-readable

class Confidence(frozen):
    score: int                              # 0..100
    band: ConfidenceBand
    contested: bool
    factors: list[ConfidenceFactor]         # the full explanation

# ---- recommendation (FINDING-OWNED) ----
class Recommendation(frozen):
    action: RecommendationAction
    category: RecommendationCategory
    priority: int                           # 0 = most urgent (inherits finding priority)
    target_type: EntityType
    target_value: str
    rationale: str                          # deterministic; cites the rule
    rule_id: str                            # provenance
    # NOTE: no finding_ids back-reference — recommendations live inside their Finding

# ---- finding ----
class Finding(frozen):
    id: str                                 # deterministic content hash (stable across runs)
    title: str                              # deterministic template (NOT AI)
    categories: frozenset[FindingCategory]
    subject_type: EntityType                # usually the searched entity; may be a related one
    subject_value: str
    severity: Severity                      # how bad IF true
    confidence: Confidence                  # how SURE
    priority: int                           # how URGENT — derived (see §4); distinct axis
    evidence: list[WeightedEvidence]        # citations (provider attribution preserved)
    relationships: list[AttributedRelationship]
    sources: list[str]                      # union of contributing providers
    rationale: str                          # deterministic explanation
    rule_ids: list[str]                     # which rules fired (provenance)
    recommendations: list[Recommendation]   # OWNED here (source of truth)
    # NEVER: AI text · mutable lifecycle status (see §8) · raw payloads · bare malicious/benign boolean

# ---- top-level output ----
class InvestigationSummary(frozen):
    entity_type: EntityType
    entity_value: str
    posture: Severity                       # aggregate (worst) severity, deterministic
    overall_confidence: Confidence
    categories: frozenset[FindingCategory]
    findings: list[Finding]                 # sorted: priority desc, then severity, then confidence
    recommendations: list[Recommendation]   # DERIVED ROLLUP: deduped + priority-sorted (read-only view)
    engine_version: str                     # reproducibility
    generated_at: datetime
```

**Finding identity:** deterministic content hash over **stable keys** — `(primary_category, subject_type, subject_value, sorted canonical evidence identities)`. Never hash free-text titles/summaries. Same inputs → same id ⇒ findings are idempotent and **diffable across runs** (the join key for Timeline and Case Management, §8). Multiple providers may contribute to one finding; corroboration raises confidence.

---

## 4. Finding axes: Severity vs Confidence vs Priority

Three orthogonal, deterministic axes — never conflated:

| Axis | Question | Derived from |
|---|---|---|
| **Severity** | How bad is it *if true*? | finding rule (evidence + dataset facts, e.g. CVSS, KEV) |
| **Confidence** | How *sure* is the engine? | the four confidence factors (§6) |
| **Priority** | How *urgently* should the analyst respond? | `f(severity, confidence, InvestigationContext)` |

**Priority** is a deterministic derivation — never user opinion, never AI. With an EMPTY context it reduces to `f(severity, confidence)`. Context (e.g. `internet_facing`, `criticality=CRITICAL`) raises priority; it can **never** raise severity or confidence. Priority orders the analyst queue and is inherited by each `Recommendation`.

---

## 5. InvestigationContext (optional engine input)

- **What:** the operational *frame* of the investigation (asset criticality, environment, internet-facing, tags, free `attributes`). Intentionally small.
- **How it enters:** an **optional parameter** to `reason()`, defaulting to **EMPTY**. Empty context = today's behavior exactly (backwards compatible).
- **Strict boundaries:**
  - Context **is NOT evidence** and is **never stored on a Finding**.
  - Context affects **Priority** and **Recommendations only**.
  - Context **must never affect Severity, Confidence, or Evidence.** (Asset criticality doesn't make a claim more *true* — only more *urgent*.)
- **Why it doesn't violate the architecture:** one more input to a pure function — deterministic, optional, untouched by providers/aggregation/AI; enters only at the reasoning boundary.
- **Population:** Phase 3.1 plumbs the parameter with an **EMPTY default and no population**. Sourcing it from a **CMDB / Asset Inventory** (and user/customer metadata) is a **future phase (3.3)**. Defining the seam now avoids a later signature break.

---

## 6. Confidence engine (deterministic — exactly four factors)

Transparent weighted sum of normalized factors, each in `[0,1]`:

| Factor | Weight | Definition |
|---|---|---|
| **Authority** | 0.35 | max authority among **supporting** evidence (AuthorityMap: NVD/MITRE/KEV ≈ 1.0; community feeds lower) |
| **Agreement** | 0.25 | `support_weight / (support_weight + contradict_weight)` on the finding's dimension |
| **Corroboration** | 0.25 | independent **authority families** in agreement, with diminishing returns — **not raw provider count** (echo-chamber guard) |
| **Freshness** | 0.15 | decay on min supporting-evidence age; **knowledge facts (CWE/CAPEC/NVD) = 1.0** (timeless) |

> **Relationship strength is removed as a separate factor.** A corroborating edge is *evidence* and is counted within Corroboration — never as its own axis (avoids double-counting).

```
score = clamp(0,100, round(100 × Σ wᵢ·fᵢ))
contested = contradict_weight is significant (past a ratio threshold)
bands: <10 or no evidence → INSUFFICIENT; <30 LOW; 30–59 MODERATE; 60–84 HIGH; ≥85 VERY_HIGH
band cap: if contested, band ≤ MODERATE — UNLESS carried by an authoritative fact (authority ≈ 1)
```

**Echo-chamber guard:** corroboration counts distinct **authority families** (e.g. all abuse.ch mirrors = one family), so redundant feeds cannot manufacture confidence.

**Hard exclusions — these must NEVER influence confidence:** asset criticality, EPSS, CISA KEV. (They affect severity/priority, not certainty.) `Confidence.factors[]` records each term's signed contribution for full explainability.

Confidence ≠ Severity ≠ Priority (§4).

---

## 7. Weighted Evidence — closed dimension enum

`WeightedEvidence.dimension` is a **closed enumeration** (no free-text), so correlation is deterministic and testable:

```
EvidenceDimension = { REPUTATION, EXPLOITATION, EXPOSURE, ATTRIBUTION,
                      WEAKNESS, CAPABILITY, INFRASTRUCTURE }
```

The EvidenceAssembler maps each `AttributedEvidence` / `Reputation` / signal-bearing `Relationship` to exactly one dimension from its evidence type + provider domain. Correlation (§ data-flow step 2) groups by `(subject, dimension)` and splits by polarity to detect agreement vs contradiction. (Enum documented here; **not implemented** in this phase.)

---

## 8. Finding status is NOT in the deterministic model

Lifecycle status (**Open / Triaged / Resolved / Suppressed**) is **explicitly excluded** from the `Finding` model. The engine is pure and reproducible: the same evidence must always yield the same finding, so mutable workflow state cannot live on it.

**Extension point:** a future **Case Management** layer attaches workflow state **keyed by the stable Finding `id`** (§3). The engine produces the immutable finding; the case layer owns status, assignment, notes, and suppression — joined, never merged.

---

## 9. Rule engine — Rule Registry (no DSL)

A lightweight, declarative, deterministic **Rule Registry** of typed objects. **A DSL is explicitly rejected:** rules are authored and reviewed by the same team that writes the code; a registry is mypy-checked, unit-testable, and versioned with the source. (Revisit only if non-engineers must author rules or the set exceeds ~30 with tenant-specific variants.)

Each rule declares:

```
id        : str        # stable, referenced in Finding.rule_ids
version    : str        # reproducibility
category   : FindingCategory          # primary category it emits
severity   : Severity                 # severity it asserts
predicate  : (context) -> bool        # pure
effect     : (context) -> FindingDraft  # emits/contributes a finding
```

Two layers, two registries: **finding rules** (evidence context → Findings) and **recommendation rules** (Findings → Recommendations).

**Deterministic finding merge:** when multiple finding rules target the same `(subject, primary_category)`, the engine **merges** them into one Finding — union the evidence, union the categories, take **max severity**, union `rule_ids` — rather than emitting duplicates. Merge order is deterministic (rules are ordered by `id`). Example finding rule: `CVSS ≥ 9 ∧ KnownExploited ∧ ATT&CK-mapped → CRITICAL Vulnerability {KNOWN_EXPLOITED, HIGH_PRIORITY}`.

---

## 10. Recommendation engine (deterministic)

- **Finding ownership:** recommendations are produced per-finding and **stored on the Finding** (`Finding.recommendations`) — the source of truth. They carry a `rule_id` and rationale, **no finding back-reference**.
- **Rollup:** `InvestigationSummary.recommendations` is a **derived, read-only view** — the union of all findings' recommendations, **deduplicated** (by `action` + target) and **priority-sorted** (priority inherited from the owning finding).
- **Conflict-resolution policy:** a deterministic, documented precedence resolves contradictory or overlapping actions during rollup (e.g. `BLOCK` outranks `MONITOR`; the highest-priority instance of a duplicated action wins). The policy is an explicit, testable component — not implicit sort order.
- **Categories (closed — do not expand):** every recommendation declares one of:

  | Category | Example actions |
  |---|---|
  | **Containment** | BLOCK, MONITOR |
  | **Investigation** | INVESTIGATE, ENRICH, THREAT_HUNT |
  | **Remediation** | PATCH_IMMEDIATELY, GENERATE_DETECTION, ESCALATE |
  | **Forensics** | COLLECT_MEMORY, ACQUIRE_DISK |

No AI, no DSL.

---

## 11. AI boundary (unchanged)

The entire engine (Evidence → Confidence → Findings → Priority → Recommendations) is deterministic, offline, reproducible. **AI is a strictly downstream, read-only consumer** of the immutable `InvestigationSummary`.

- **Must stay deterministic:** detection, routing, results, aggregation, evidence weighting, confidence, severity, priority, findings, categories, recommendations.
- **AI may generate (grounded + cited, never authoritative):** narrative summaries, finding explanations, analyst chat/Q&A, report prose, **draft** detection logic (validated deterministically).
- AI never writes back into a Finding/Confidence/Recommendation and never changes a score. If AI is absent, the platform fully works. One-directional flow = auditability.

---

## 12. Future integration strategy (no redesign)

**Producers of evidence** — implement the *existing* `IntelligenceProvider` / `ReferenceProvider` contract → `IntelligenceResult` → existing routing + aggregation → the engine reasons automatically:

| Provider | Contributes | Engine leverage |
|---|---|---|
| EPSS | exploit-probability evidence (CVE) | exploitation dimension / severity (never confidence) |
| CISA KEV | authoritative `KnownExploited` fact | category + severity (never confidence) |
| GreyNoise | benign/noise reputation | contradiction path (lowers confidence, raises `contested`) |
| WHOIS / RDAP / DNS | infra context + relationships | exposure/attribution/infrastructure dimensions |
| Shodan | open-port/exposure evidence | Exposure findings |
| VirusTotal | multi-engine reputation | high-corroboration reputation (one family) |
| Report Parser | entities + evidence | normal flow (uses the related-entity seam) |
| Local KB / User IOC Lists | internal allow/deny evidence | very high authority (AuthorityMap override) |

The only engine-side touches to *optimize* a new source are **additive data**: an AuthorityMap entry and/or new rules — never structural change.

**Consumers of findings** — read `InvestigationSummary`, write nothing back: **AI Summary**, **Detection Engineering** (findings + ATT&CK → YARA/Sigma drafts), **Graph Explorer** (ingests relationships), **Timeline** (diffs findings by stable id), **Case Management** (attaches status by id, §8). Timeline/Case require persisted summary snapshots — an additive persistence layer (Phase 3.3), not an engine change.

---

## 13. Implementation roadmap (approved)

| Phase | Scope |
|---|---|
| **3.1a** | Canonical models · `EvidenceAssembler` · `ConfidenceScorer` · `InvestigationSummary` integration (additive `/investigate` field) |
| **3.1b** | Finding Rule Engine · deterministic finding merge |
| **3.1c** | Recommendation Engine · recommendation rollup · conflict-resolution policy |
| **3.1d** | `InvestigationContext` plumbing (EMPTY default) · derived Priority |
| **3.1e** | Frontend Findings UI (provider-independent consumer) |
| **3.2** | AI Summary (downstream, read-only) |
| **3.3** | Context population (CMDB/Asset Inventory) · Timeline · persistence |

Each 3.1 slice is independently shippable, deterministic, mypy/ruff/pytest-clean, and gated behind an additive API field — de-risking confidence calibration before recommendations and UI depend on it.

---

## 14. Preserved (unchanged by this phase)

Provider Framework · Reference Framework · Investigation Pipeline · AI Boundary · deterministic philosophy · existing diagrams. The engine **consumes** `AggregatedResult` and adds one additive output; it changes none of the above.

---

## 15. Change log vs Phase 3.0 draft (approved minor changes)

1. **Recommendations are Finding-owned**; `InvestigationSummary` exposes a **derived, deduped, priority-sorted rollup**; recommendation→finding back-references removed.
2. **InvestigationContext** introduced as an optional `reason()` input (EMPTY default); affects Priority + Recommendations only; never severity/confidence/evidence; CMDB population deferred to 3.3.
3. **Priority** documented as a third, deterministic axis distinct from severity and confidence.
4. **Confidence** reduced to **four** factors (Authority, Agreement, Corroboration, Freshness); relationship strength removed; corroboration counts **authority families**; asset criticality / EPSS / KEV explicitly barred from confidence.
5. **Rule Registry** retained, **DSL rejected**; each rule declares id/version/category/severity/predicate/effect; deterministic finding-merge documented.
6. **Recommendation** model gains finding ownership, rollup, conflict-resolution policy, and four closed categories (Containment / Investigation / Remediation / Forensics).
7. **WeightedEvidence.dimension** is now a **closed enum** (`EvidenceDimension`).
8. **Finding status** explicitly excluded from the deterministic model; Case Management attaches workflow state via the stable Finding id (extension point).
9. **Roadmap** replaced with the 3.1a → 3.3 sequence above.
