"""The Recommendation Engine — deterministic, finding-only (Phase 3.1c).

Recommendations are generated *only* from :class:`Finding` objects. This layer
never inspects threat-intelligence providers, knowledge providers, aggregated
evidence, raw reputation, or API responses — its sole input is findings.

Each :class:`RecommendationRule` is a typed Python class declaring its gate
(applicable finding categories, minimum severity, minimum confidence) and an
``effect`` that drafts recommendations. Recommendations are owned by their
finding; :class:`RecommendationEngine.rollup` derives the deduplicated,
conflict-resolved, priority-ordered summary list, retaining provenance back to
the originating finding ids.

No DSL, no external rule formats, no AI. Five validation rules; no more.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar

from .models import (
    ConfidenceBand,
    Finding,
    FindingCategory,
    Recommendation,
    RecommendationAction,
    RecommendationCategory,
    Severity,
)

# --------------------------------------------------------------------------- #
# Priority & conflict policy (deterministic, documented)
# --------------------------------------------------------------------------- #

# Intra-severity action ordering (lower = more urgent). Combined with finding
# severity to produce a deterministic recommendation priority.
_ACTION_RANK: dict[RecommendationAction, int] = {
    RecommendationAction.BLOCK: 0,
    RecommendationAction.PATCH_IMMEDIATELY: 1,
    RecommendationAction.ESCALATE: 2,
    RecommendationAction.COLLECT_MEMORY: 10,
    RecommendationAction.ACQUIRE_DISK: 11,
    RecommendationAction.INVESTIGATE: 20,
    RecommendationAction.THREAT_HUNT: 21,
    RecommendationAction.ENRICH: 30,
    RecommendationAction.GENERATE_DETECTION: 40,
    RecommendationAction.MONITOR: 50,
    RecommendationAction.NO_ACTION_NEEDED: 99,
}
_DEFAULT_ACTION_RANK = 60

_BAND_RANK: dict[ConfidenceBand, int] = {
    ConfidenceBand.INSUFFICIENT: 0,
    ConfidenceBand.LOW: 1,
    ConfidenceBand.MODERATE: 2,
    ConfidenceBand.HIGH: 3,
    ConfidenceBand.VERY_HIGH: 4,
}

# Conflict policy: a superior action supersedes the listed inferior actions when
# both target the same entity. "Block/Isolate" outranks "Monitor/Observe";
# "Patch immediately" outranks "Monitor".
_SUPERSEDES: dict[RecommendationAction, frozenset[RecommendationAction]] = {
    RecommendationAction.BLOCK: frozenset({RecommendationAction.MONITOR}),
    RecommendationAction.PATCH_IMMEDIATELY: frozenset({RecommendationAction.MONITOR}),
}


def _priority(severity: Severity, action: RecommendationAction) -> int:
    """Deterministic priority (0 = most urgent): severity first, then action."""
    severity_band = (int(Severity.CRITICAL) - int(severity)) * 100
    return severity_band + _ACTION_RANK.get(action, _DEFAULT_ACTION_RANK)


def _band_rank(band: ConfidenceBand) -> int:
    return _BAND_RANK[band]


# --------------------------------------------------------------------------- #
# Rule interface
# --------------------------------------------------------------------------- #


class RecommendationRule(ABC):
    """Base class for deterministic recommendation rules.

    The predicate is the declared gate: the finding shares one of
    ``applicable_categories`` and meets ``min_severity`` and ``min_confidence``.
    Rules implement ``effect`` only.
    """

    id: ClassVar[str]
    version: ClassVar[str]
    category: ClassVar[RecommendationCategory]  # the rule's primary category
    applicable_categories: ClassVar[frozenset[FindingCategory]]
    min_severity: ClassVar[Severity]
    min_confidence: ClassVar[ConfidenceBand]

    def predicate(self, finding: Finding) -> bool:
        """True if the finding meets this rule's category/severity/confidence gate."""
        return (
            bool(self.applicable_categories & finding.categories)
            and finding.severity >= self.min_severity
            and _band_rank(finding.confidence.band) >= _band_rank(self.min_confidence)
        )

    @abstractmethod
    def effect(self, finding: Finding) -> tuple[Recommendation, ...]:
        """Draft recommendations for ``finding``. Only called when predicate holds."""


def _rec(
    finding: Finding,
    action: RecommendationAction,
    category: RecommendationCategory,
    rationale: str,
    rule_id: str,
) -> Recommendation:
    """Build a finding-owned recommendation (finding_ids stays empty)."""
    return Recommendation(
        action=action,
        category=category,
        priority=_priority(finding.severity, action),
        target_type=finding.subject_type,
        target_value=finding.subject_value,
        rationale=rationale,
        rule_id=rule_id,
    )


# --------------------------------------------------------------------------- #
# The five validation rules
# --------------------------------------------------------------------------- #


class CriticalVulnerabilityRecommendation(RecommendationRule):
    id = "rec.vuln.critical"
    version = "1"
    category = RecommendationCategory.REMEDIATION
    applicable_categories = frozenset({FindingCategory.VULNERABILITY})
    min_severity = Severity.HIGH
    min_confidence = ConfidenceBand.MODERATE

    def effect(self, finding: Finding) -> tuple[Recommendation, ...]:
        return (
            _rec(
                finding,
                RecommendationAction.PATCH_IMMEDIATELY,
                RecommendationCategory.REMEDIATION,
                "Patch immediately to remediate the vulnerability.",
                self.id,
            ),
            _rec(
                finding,
                RecommendationAction.INVESTIGATE,
                RecommendationCategory.INVESTIGATION,
                "Verify exposure of affected assets.",
                self.id,
            ),
        )


class MaliciousInfrastructureRecommendation(RecommendationRule):
    id = "rec.infra.malicious"
    version = "1"
    category = RecommendationCategory.CONTAINMENT
    applicable_categories = frozenset({FindingCategory.MALICIOUS_INFRASTRUCTURE})
    min_severity = Severity.MEDIUM
    min_confidence = ConfidenceBand.MODERATE

    def effect(self, finding: Finding) -> tuple[Recommendation, ...]:
        return (
            _rec(
                finding,
                RecommendationAction.BLOCK,
                RecommendationCategory.CONTAINMENT,
                "Block communication with this infrastructure.",
                self.id,
            ),
            _rec(
                finding,
                RecommendationAction.THREAT_HUNT,
                RecommendationCategory.INVESTIGATION,
                "Hunt for additional connections to this infrastructure.",
                self.id,
            ),
        )


class KnownMalwareRecommendation(RecommendationRule):
    id = "rec.malware.known"
    version = "1"
    category = RecommendationCategory.CONTAINMENT
    applicable_categories = frozenset({FindingCategory.MALWARE})
    min_severity = Severity.MEDIUM
    min_confidence = ConfidenceBand.MODERATE

    def effect(self, finding: Finding) -> tuple[Recommendation, ...]:
        return (
            _rec(
                finding,
                RecommendationAction.BLOCK,
                RecommendationCategory.CONTAINMENT,
                "Isolate the affected host.",
                self.id,
            ),
            _rec(
                finding,
                RecommendationAction.INVESTIGATE,
                RecommendationCategory.INVESTIGATION,
                "Perform a malware scan on the affected host.",
                self.id,
            ),
        )


class ThreatActorRecommendation(RecommendationRule):
    id = "rec.actor.attributed"
    version = "1"
    category = RecommendationCategory.INVESTIGATION
    applicable_categories = frozenset({FindingCategory.THREAT_ACTOR})
    min_severity = Severity.LOW
    min_confidence = ConfidenceBand.MODERATE

    def effect(self, finding: Finding) -> tuple[Recommendation, ...]:
        return (
            _rec(
                finding,
                RecommendationAction.INVESTIGATE,
                RecommendationCategory.INVESTIGATION,
                "Investigate related IOCs and infrastructure.",
                self.id,
            ),
            _rec(
                finding,
                RecommendationAction.ENRICH,
                RecommendationCategory.INVESTIGATION,
                "Review historical activity associated with this actor.",
                self.id,
            ),
        )


class AttackTechniqueRecommendation(RecommendationRule):
    id = "rec.attack.technique"
    version = "1"
    category = RecommendationCategory.INVESTIGATION
    applicable_categories = frozenset({FindingCategory.ATTACK_PATTERN})
    min_severity = Severity.LOW
    min_confidence = ConfidenceBand.MODERATE

    def effect(self, finding: Finding) -> tuple[Recommendation, ...]:
        return (
            _rec(
                finding,
                RecommendationAction.THREAT_HUNT,
                RecommendationCategory.INVESTIGATION,
                "Search for additional evidence of this technique.",
                self.id,
            ),
            _rec(
                finding,
                RecommendationAction.GENERATE_DETECTION,
                RecommendationCategory.REMEDIATION,
                "Review detection coverage mapped to this technique.",
                self.id,
            ),
        )


DEFAULT_RECOMMENDATION_RULES: tuple[type[RecommendationRule], ...] = (
    CriticalVulnerabilityRecommendation,
    MaliciousInfrastructureRecommendation,
    KnownMalwareRecommendation,
    ThreatActorRecommendation,
    AttackTechniqueRecommendation,
)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


class DuplicateRecommendationRuleError(ValueError):
    """Raised when registering a recommendation rule whose id already exists."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"a recommendation rule with id {rule_id!r} is already registered")
        self.rule_id = rule_id


class RecommendationRegistry:
    """Holds recommendation rules keyed by unique id, in deterministic order."""

    def __init__(self) -> None:
        self._rules: dict[str, RecommendationRule] = {}

    def register(self, rule: RecommendationRule) -> None:
        if rule.id in self._rules:
            raise DuplicateRecommendationRuleError(rule.id)
        self._rules[rule.id] = rule

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[RecommendationRule, ...]:
        return tuple(self._rules[rule_id] for rule_id in sorted(self._rules))


def build_default_recommendation_registry() -> RecommendationRegistry:
    """Registry populated with the five Phase 3.1c validation rules."""
    registry = RecommendationRegistry()
    for rule_cls in DEFAULT_RECOMMENDATION_RULES:
        registry.register(rule_cls())
    return registry


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

_RecKey = tuple[str, str, str]  # (action, target_type, target_value)


def _rec_key(rec: Recommendation) -> _RecKey:
    return (rec.action.value, rec.target_type.value, rec.target_value)


class RecommendationEngine:
    """Generates finding-owned recommendations and the summary rollup."""

    def __init__(self, registry: RecommendationRegistry) -> None:
        self._registry = registry

    def for_finding(self, finding: Finding) -> list[Recommendation]:
        """Recommendations owned by ``finding`` (deduped, priority-ordered)."""
        drafted = [
            rec
            for rule in self._registry.rules
            if rule.predicate(finding)
            for rec in rule.effect(finding)
        ]
        return _dedupe(drafted)

    def rollup(self, findings: Iterable[Finding]) -> list[Recommendation]:
        """Derive the deduped, conflict-resolved, priority-ordered summary list.

        Each rollup item retains ``finding_ids`` back to every originating
        finding. The source of truth remains each finding's own recommendations.
        """
        attributed: list[Recommendation] = []
        for finding in findings:
            for rec in finding.recommendations:
                attributed.append(rec.model_copy(update={"finding_ids": [finding.id]}))

        merged = _merge(attributed)
        resolved = _resolve_conflicts(merged)
        return sorted(resolved, key=lambda r: (r.priority, r.action.value, r.target_value))


# --------------------------------------------------------------------------- #
# De-duplication, merge, conflict resolution
# --------------------------------------------------------------------------- #


def _dedupe(recs: list[Recommendation]) -> list[Recommendation]:
    """De-duplicate within a finding by (action, target); keep most urgent."""
    best: dict[_RecKey, Recommendation] = {}
    for rec in recs:
        key = _rec_key(rec)
        current = best.get(key)
        if current is None or rec.priority < current.priority:
            best[key] = rec
    return sorted(best.values(), key=lambda r: (r.priority, r.action.value, r.target_value))


def _merge(recs: list[Recommendation]) -> list[Recommendation]:
    """Merge identical (action, target) recommendations across findings.

    The most-urgent instance wins; ``finding_ids`` are unioned (sorted).
    """
    merged: dict[_RecKey, Recommendation] = {}
    ids: dict[_RecKey, set[str]] = {}
    for rec in recs:
        key = _rec_key(rec)
        ids.setdefault(key, set()).update(rec.finding_ids)
        current = merged.get(key)
        if current is None or rec.priority < current.priority:
            merged[key] = rec
    return [rec.model_copy(update={"finding_ids": sorted(ids[key])}) for key, rec in merged.items()]


def _resolve_conflicts(recs: list[Recommendation]) -> list[Recommendation]:
    """Drop recommendations superseded by a higher-precedence action on the same target."""
    by_target: dict[tuple[str, str], set[RecommendationAction]] = {}
    for rec in recs:
        by_target.setdefault((rec.target_type.value, rec.target_value), set()).add(rec.action)

    survivors: list[Recommendation] = []
    for rec in recs:
        present = by_target[(rec.target_type.value, rec.target_value)]
        superseded = any(
            rec.action in _SUPERSEDES.get(other, frozenset())
            for other in present
            if other is not rec.action
        )
        if not superseded:
            survivors.append(rec)
    return survivors
