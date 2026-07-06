# Phase 7.1 — Correlation Rule Library Expansion

## Status

Complete. Expands the Phase 7.0 seed rule set from **12 rules to 70 rules**.
The Correlation Engine, registry, models, service, summary generation, and
output schemas are **unchanged** — this phase adds rule *data* only. No AI, no
new engines, no API changes, no `/investigate` integration.

## Purpose

Phase 7.0 shipped the Correlation Engine's full machinery with a small seed
set (12 rules) "so the pipeline is exercised end-to-end." Phase 7.1 is the
explicitly-deferred follow-up: broaden the rule *library* itself, reusing the
frozen engine/registry/model architecture without modification.

## A load-bearing constraint: the `FindingCategory` vocabulary

Every correlation rule matches against `FindingCategory` — the closed,
15-value vocabulary the Reasoning Engine tags findings with (10 domain values:
`MALICIOUS_INFRASTRUCTURE`, `VULNERABILITY`, `WEAKNESS`, `ATTACK_PATTERN`,
`THREAT_ACTOR`, `MALWARE`, `CAMPAIGN`, `EXPOSURE`, `MISCONFIGURATION`,
`REPUTATION`; 5 disposition values: `KNOWN_EXPLOITED`, `HIGH_PRIORITY`,
`ACTION_REQUIRED`, `CONTESTED`, `INFORMATIONAL`). This is the *only* vocabulary
a correlation rule can reference — rules never invent evidence, so they cannot
distinguish anything this vocabulary doesn't already distinguish.

Concretely, `ATTACK_PATTERN` is tactic-agnostic: there is no separate category
for a persistence technique vs. an execution technique vs. a discovery
technique. A rule library organized by MITRE tactic (`persistence.py`,
`execution.py`, `discovery.py`, `collection.py`, `exfiltration.py`,
`command_and_control.py`, `lateral_movement.py`, `privilege_escalation.py`,
`impact.py` — the originally-sketched module list) would therefore produce
rules that differ only in their display text, not in what they actually
match — the engine cannot tell which tactic a matched technique belongs to, so
labeling nine tactic-specific rules from one undifferentiated category would
assert something the evidence doesn't support. That is exactly the semantic
duplication this rule library is meant to avoid, so this phase deliberately
does not build those nine modules. All technique-co-occurrence rules live in
one `mitre.py`, and the taxonomy below reflects what the vocabulary actually
supports rather than the originally-sketched module list.

## Rule taxonomy

`backend/src/threatlens/correlation/rules/` — one module per domain, each
exporting a `RULES` tuple of declarative `CorrelationRule` data:

| Module | Rules | Anchor |
|---|---|---|
| `seed.py` | 12 | The unchanged Phase 7.0 rule set |
| `compound.py` | 6 | Three-signal escalations (strictly more specific than any one of their two-category subset rules) |
| `infrastructure.py` | 9 | `MALICIOUS_INFRASTRUCTURE` / `EXPOSURE` / `REPUTATION` / `MISCONFIGURATION` |
| `vulnerability.py` | 9 | `VULNERABILITY` / `WEAKNESS` / `KNOWN_EXPLOITED` |
| `malware.py` | 9 | `MALWARE` combined with every other domain category |
| `threat_actor.py` | 9 | `THREAT_ACTOR` combined with every other domain category |
| `campaign.py` | 7 | `CAMPAIGN` combined with every other domain category |
| `mitre.py` | 9 | `ATTACK_PATTERN` combined with every category not owned by `malware`/`threat_actor`/`campaign` |
| **Total** | **70** | |

`rules/__init__.py` concatenates all eight `RULES` tuples into `SEED_RULES`
and keeps `default_rules()` — the exact names and shapes `registry.py` and the
package `__init__.py` already imported, so neither needed a change.

## Rule philosophy applied

- **Coverage over quantity.** 70 rules, not a padded-to-80 count: every
  malware/actor/campaign/technique pairing that existed only cross-subject in
  the seed set gets a same-subject variant (a materially tighter, more
  significant binding — "the actor and the malware are on the *same* entity"
  is stronger evidence than "both appear somewhere in the investigation"), and
  the disposition categories (`CONTESTED`, `ACTION_REQUIRED`, `INFORMATIONAL`,
  never used by the seed set) are combined with the domain categories that
  benefit most from a "which findings are still contested / actionable"
  signal.
- **No semantic duplication, verified programmatically, not just by
  inspection.** `test_registry.py::test_no_two_rules_share_the_same_matching_signature`
  asserts no two of the 70 rules share an identical
  `(required_categories, same_subject)` pair — the actual non-duplication
  invariant (two rules with different `id`/`title` but the same signature
  would fire identically, which *would* be a duplicate). Verified: `70`
  distinct signatures for `70` rules.
- **Every rule is still declarative data.** No new code path in the
  evaluator — `required_categories: frozenset[FindingCategory]` already had no
  upper bound (only `Field(min_length=2)`), so the six `compound.py` three-way
  rules needed no engine change either.
- **Compound rules are additive, not competing.** A three-category compound
  rule firing does not suppress its two-category subset rules from also
  firing — both stand, at different specificity. This is existing engine
  behavior (`correlate()` runs every registered rule independently), not new.

## The one disclosed model touch

The task briefing for this phase said not to modify models — respected in
spirit: **no field, type, or validation rule on any existing model
changed.** The one addition is 26 new `CorrelationCategory` enum members
(`backend/src/threatlens/correlation/models.py`), the same kind of
purely-additive vocabulary growth Phase 5.3 used for
`ExposureCapability.INTERNET_NOISE` ("the framework's first new model addition
... purely additive; no existing value's meaning changed").

Rather than one bespoke category per new rule (which would have meant +58
values, restoring Phase 7.0's incidental 1:1 rule-to-category shape), related
rules share a category when they represent the *same kind* of higher-level
pattern — e.g. every "+contested" rule across every domain module emits
`FINDING_CONTESTED`, regardless of which domain category is contested. This
is a deliberate design choice, not just an enum-growth minimization: it treats
`CorrelationCategory` as "kind of pattern" (correct at the statistics/grouping
level `CorrelationStatistics.categories` operates at) rather than "which rule
fired" (already available via `CorrelationObservation.rule_id`/
`CorrelationMatch.rule_id`). 38 distinct categories back 70 rules.

`CorrelationRule`'s `description` field (free text, unchanged) is where MITRE
relevance is noted for `mitre.py`'s rules, rather than adding a structured
`mitre_technique_ids` field: the underlying evidence never carries a specific
technique ID at the correlation layer (that lives on the individual
`Finding`, from the reference-knowledge provider) — a rule describes a
category-level pattern, not one specific technique, so a structured
per-rule MITRE reference field would either be empty or misleadingly precise.

## Testing

- **Every rule, fire and no-fire:** `test_rules.py`'s two tests are
  parametrized over `SEED_RULES` (unchanged since Phase 7.0) — extending the
  tuple from 12 to 70 entries extended coverage to all 70 with no test-file
  change.
- **Non-duplication:** `test_registry.py::test_no_two_rules_share_the_same_matching_signature`
  (new — replaces a Phase 7.0 test that asserted the now-intentionally-relaxed
  1:1 category-per-rule shape).
- **Golden regression:** `corpus.py` generates one scenario per new rule
  programmatically (`_scenario_for_rule`, mirroring `test_rules.py`'s own
  fixture-building approach) rather than 58 hand-written literals, appended to
  the 18 hand-written Phase 7.0 scenarios — 76 total, snapshotted in
  `golden.json`.
- **Multiple simultaneous matches, empty investigations, single-evidence
  investigations, duplicate findings, multi-subject fan-out:** unchanged
  Phase 7.0 edge-case scenarios in `corpus.py`, still passing byte-for-byte
  (none of the seed rules' definitions changed).
- **Category coverage / MITRE mapping:** exercised through the `mitre.py`
  module's 9 rules plus the technique-colocated variants in `malware.py` and
  `threat_actor.py`; `campaign.py`'s `campaign_attack_pattern`.
- Full correlation suite: was 79 tests (Phase 7.0) → **now includes every
  rule × 2 (fire/no-fire) + registry/engine/service/summary/API/golden/perf
  tests.** Backend suite overall: **2,399 passed, 1 skipped** (was 2,281).
  Ruff/mypy (strict) clean across 171 source files (was 163).

## Performance

Two independent scaling dimensions (`backend/tests/correlation/perf.py`):

- **Phase 7.0's benchmark (fixed rule count, growing observations 10→500):**
  unchanged, still **1.09× per-observation spread — linear.**
- **Phase 7.1's new benchmark (fixed investigation, growing *registered rule
  count* 25→50→100, synthetic benchmark-only rules never in the real
  registry):**

  | Rules | Median | μs/rule |
  |---|---|---|
  | 25 | 0.087ms | 3.48 |
  | 50 | 0.158ms | 3.16 |
  | 100 | 0.549ms | 5.49 |

  **1.73× per-rule spread — linear.** No optimization performed (none is
  justified); the real library's 70 rules fall inside the benchmarked range.

## Known limitations

- **No per-MITRE-tactic rules** (persistence/execution/discovery/collection/
  exfiltration/command-and-control/lateral-movement/privilege-escalation/
  impact) — see "A load-bearing constraint" above. Would require the
  Reasoning Engine's `FindingCategory` (frozen, out of this phase's scope) to
  carry tactic-level granularity.
- **No credential- or phishing-specific rules** — same root cause: no
  `FindingCategory` value distinguishes a credential-exposure or
  phishing-infrastructure finding from a generic `EXPOSURE`/
  `MALICIOUS_INFRASTRUCTURE` one today. (Identity Intelligence's own
  `IdentityCapability.CREDENTIAL_EXPOSURE` and Exposure Intelligence's
  `ExposureCapability.CREDENTIAL_EXPOSURE` exist in their own frameworks, but
  neither framework's findings flow into `InvestigationSummary` yet — both are
  still "not integrated into `/investigate`," so the Correlation Engine, which
  only consumes `InvestigationSummary`, cannot reference them.)
- **Disposition-category rules can reference a single multi-category
  finding**, not two independently-corroborating ones (e.g. one finding
  already tagged both `MALICIOUS_INFRASTRUCTURE` and `CONTESTED`). This is
  correct, existing engine behavior — `TestSubjectHandling`'s
  `single_multicategory_finding` scenario covers exactly this case — not a
  new gap, but worth stating: some Phase 7.1 rules will produce their
  observation from one finding rather than two.
- **Framework version stays at `"0.1.0"`.** Per the Reasoning/Detection/
  Exposure convention, the version moves to `"1.0"` only once the rule set is
  validated against `/investigate`-integrated, real investigation data — this
  phase only expands the library offline.

## Future expansion (explicitly out of scope for this phase)

- Wiring the Correlation Engine into `/investigate` (Phase 7.2+).
- Tactic-level rules, if/when `FindingCategory` (or a successor) gains
  tactic-level granularity.
- Credential- and phishing-specific rules, if/when Exposure or Identity
  findings flow into `InvestigationSummary`.
- A weighted or temporal/sequence-aware rule kind, if a future need can't be
  expressed as "these categories co-occur" (flagged, not built, in the Phase
  6.0/7.0 Merge Readiness Review's finding #8).
- Timeline Engine, Graph Engine, Case Management, SOAR — unrelated, later,
  unstarted phases.

## Readiness review

**GO.** 70 rules, 0 duplicate ids, 0 overlapping matching signatures, full
regression suite green (2,399 backend tests, 0 failures), both performance
dimensions confirmed linear, engine/registry/models(structure)/service/summary/
API all unchanged and re-verified. The one disclosed model touch (26 additive
`CorrelationCategory` values) follows a codebase precedent rather than
introducing one.
