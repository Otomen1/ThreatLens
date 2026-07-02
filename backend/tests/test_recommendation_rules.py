"""Tests for the five Phase 3.1c recommendation rules (predicate gate + effect).

Each rule consumes a Finding only. Predicate is the declared gate (category +
min severity + min confidence); effect drafts the recommended actions.
"""

from __future__ import annotations

from threatlens.entities.types import EntityType
from threatlens.reasoning.models import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    RecommendationAction,
    RecommendationCategory,
    Severity,
)
from threatlens.reasoning.recommendations import (
    AttackTechniqueRecommendation,
    CriticalVulnerabilityRecommendation,
    KnownMalwareRecommendation,
    MaliciousInfrastructureRecommendation,
    ThreatActorRecommendation,
)


def _finding(
    categories: set[FindingCategory],
    severity: Severity,
    *,
    band: ConfidenceBand = ConfidenceBand.HIGH,
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "1.2.3.4",
) -> Finding:
    return Finding(
        id="fnd_test",
        title="t",
        categories=frozenset(categories),
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=Confidence(score=70, band=band),
    )


def _actions(recs: tuple) -> set[RecommendationAction]:
    return {r.action for r in recs}


# --------------------------------------------------------------------------- #


class TestCriticalVulnerabilityRecommendation:
    rule = CriticalVulnerabilityRecommendation()

    def test_fires_and_drafts_patch_and_verify(self) -> None:
        f = _finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL)
        assert self.rule.predicate(f)
        recs = self.rule.effect(f)
        assert _actions(recs) == {
            RecommendationAction.PATCH_IMMEDIATELY,
            RecommendationAction.INVESTIGATE,
        }
        patch = next(r for r in recs if r.action is RecommendationAction.PATCH_IMMEDIATELY)
        assert patch.category is RecommendationCategory.REMEDIATION

    def test_gated_by_category(self) -> None:
        assert not self.rule.predicate(_finding({FindingCategory.MALWARE}, Severity.CRITICAL))

    def test_gated_by_severity(self) -> None:
        assert not self.rule.predicate(_finding({FindingCategory.VULNERABILITY}, Severity.MEDIUM))

    def test_gated_by_confidence(self) -> None:
        f = _finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL, band=ConfidenceBand.LOW)
        assert not self.rule.predicate(f)


class TestMaliciousInfrastructureRecommendation:
    rule = MaliciousInfrastructureRecommendation()

    def test_fires_and_drafts_block_and_hunt(self) -> None:
        f = _finding({FindingCategory.MALICIOUS_INFRASTRUCTURE}, Severity.HIGH)
        assert self.rule.predicate(f)
        recs = self.rule.effect(f)
        assert _actions(recs) == {RecommendationAction.BLOCK, RecommendationAction.THREAT_HUNT}
        block = next(r for r in recs if r.action is RecommendationAction.BLOCK)
        assert block.category is RecommendationCategory.CONTAINMENT

    def test_gated_by_category(self) -> None:
        assert not self.rule.predicate(_finding({FindingCategory.VULNERABILITY}, Severity.HIGH))


class TestKnownMalwareRecommendation:
    rule = KnownMalwareRecommendation()

    def test_fires_and_drafts_isolate_and_scan(self) -> None:
        f = _finding({FindingCategory.MALWARE}, Severity.HIGH)
        assert self.rule.predicate(f)
        recs = self.rule.effect(f)
        assert _actions(recs) == {RecommendationAction.BLOCK, RecommendationAction.INVESTIGATE}
        assert any(r.category is RecommendationCategory.CONTAINMENT for r in recs)


class TestThreatActorRecommendation:
    rule = ThreatActorRecommendation()

    def test_fires_and_drafts_investigate_and_enrich(self) -> None:
        f = _finding({FindingCategory.THREAT_ACTOR}, Severity.MEDIUM)
        assert self.rule.predicate(f)
        recs = self.rule.effect(f)
        assert _actions(recs) == {RecommendationAction.INVESTIGATE, RecommendationAction.ENRICH}
        assert all(r.category is RecommendationCategory.INVESTIGATION for r in recs)


class TestAttackTechniqueRecommendation:
    rule = AttackTechniqueRecommendation()

    def test_fires_and_drafts_hunt_and_detections(self) -> None:
        f = _finding({FindingCategory.ATTACK_PATTERN}, Severity.MEDIUM)
        assert self.rule.predicate(f)
        recs = self.rule.effect(f)
        assert _actions(recs) == {
            RecommendationAction.THREAT_HUNT,
            RecommendationAction.GENERATE_DETECTION,
        }
        detect = next(r for r in recs if r.action is RecommendationAction.GENERATE_DETECTION)
        assert detect.category is RecommendationCategory.REMEDIATION

    def test_gated_by_confidence(self) -> None:
        f = _finding(
            {FindingCategory.ATTACK_PATTERN}, Severity.MEDIUM, band=ConfidenceBand.INSUFFICIENT
        )
        assert not self.rule.predicate(f)
