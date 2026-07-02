"""Tests for the RecommendationEngine: generation, rollup, conflict, ordering.

Covers finding-only generation, finding ownership, deduplicated rollup with
finding-id provenance, conflict resolution, stable ordering, repeated-execution
determinism, empty/unsupported findings, and end-to-end integration via reason().
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.entities.types import EntityType
from threatlens.reasoning.models import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    Recommendation,
    RecommendationAction,
    RecommendationCategory,
    Severity,
)
from threatlens.reasoning.recommendations import (
    RecommendationEngine,
    build_default_recommendation_registry,
)


def _engine() -> RecommendationEngine:
    return RecommendationEngine(build_default_recommendation_registry())


def _finding(
    categories: set[FindingCategory],
    severity: Severity = Severity.HIGH,
    *,
    band: ConfidenceBand = ConfidenceBand.HIGH,
    fid: str = "fnd_test",
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "1.2.3.4",
    recommendations: tuple[Recommendation, ...] = (),
) -> Finding:
    return Finding(
        id=fid,
        title="t",
        categories=frozenset(categories),
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=Confidence(score=70, band=band),
        recommendations=list(recommendations),
    )


def _rec(
    action: RecommendationAction,
    *,
    priority: int = 100,
    target_value: str = "1.2.3.4",
    finding_ids: tuple[str, ...] = (),
) -> Recommendation:
    return Recommendation(
        action=action,
        category=RecommendationCategory.CONTAINMENT,
        priority=priority,
        target_type=EntityType.IPV4,
        target_value=target_value,
        rationale="r",
        rule_id="x",
        finding_ids=list(finding_ids),
    )


# --------------------------------------------------------------------------- #
# Generation (finding-owned)
# --------------------------------------------------------------------------- #


class TestForFinding:
    def test_generates_recommendations(self) -> None:
        recs = _engine().for_finding(_finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL))
        assert {r.action for r in recs} == {
            RecommendationAction.PATCH_IMMEDIATELY,
            RecommendationAction.INVESTIGATE,
        }

    def test_finding_owned_recs_have_empty_finding_ids(self) -> None:
        recs = _engine().for_finding(_finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL))
        assert all(r.finding_ids == [] for r in recs)

    def test_low_confidence_finding_gets_no_recommendations(self) -> None:
        recs = _engine().for_finding(
            _finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL, band=ConfidenceBand.LOW)
        )
        assert recs == []

    def test_unsupported_category_gets_no_recommendations(self) -> None:
        recs = _engine().for_finding(_finding({FindingCategory.EXPOSURE}, Severity.HIGH))
        assert recs == []

    def test_ordered_by_priority(self) -> None:
        recs = _engine().for_finding(_finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL))
        priorities = [r.priority for r in recs]
        assert priorities == sorted(priorities)


# --------------------------------------------------------------------------- #
# Rollup
# --------------------------------------------------------------------------- #


class TestRollup:
    def test_empty_findings_empty_rollup(self) -> None:
        assert _engine().rollup([]) == []

    def test_dedupe_merges_finding_ids(self) -> None:
        rec = _rec(RecommendationAction.INVESTIGATE, priority=120)
        f1 = _finding({FindingCategory.MALWARE}, fid="fnd_1", recommendations=(rec,))
        f2 = _finding({FindingCategory.MALWARE}, fid="fnd_2", recommendations=(rec,))
        rollup = _engine().rollup([f1, f2])
        assert len(rollup) == 1
        assert rollup[0].finding_ids == ["fnd_1", "fnd_2"]

    def test_rollup_items_have_provenance(self) -> None:
        rec = _rec(RecommendationAction.BLOCK)
        f = _finding(
            {FindingCategory.MALICIOUS_INFRASTRUCTURE}, fid="fnd_abc", recommendations=(rec,)
        )
        rollup = _engine().rollup([f])
        assert rollup[0].finding_ids == ["fnd_abc"]

    def test_sorted_by_priority(self) -> None:
        low = _rec(RecommendationAction.GENERATE_DETECTION, priority=240, target_value="a")
        high = _rec(RecommendationAction.BLOCK, priority=100, target_value="a")
        f = _finding({FindingCategory.MALWARE}, recommendations=(low, high))
        rollup = _engine().rollup([f])
        assert [r.priority for r in rollup] == sorted(r.priority for r in rollup)
        assert rollup[0].action is RecommendationAction.BLOCK


# --------------------------------------------------------------------------- #
# Conflict resolution
# --------------------------------------------------------------------------- #


class TestConflictResolution:
    def test_block_supersedes_monitor_same_target(self) -> None:
        block = _rec(RecommendationAction.BLOCK, priority=100, target_value="1.2.3.4")
        monitor = _rec(RecommendationAction.MONITOR, priority=150, target_value="1.2.3.4")
        f = _finding({FindingCategory.MALICIOUS_INFRASTRUCTURE}, recommendations=(block, monitor))
        rollup = _engine().rollup([f])
        actions = {r.action for r in rollup}
        assert RecommendationAction.BLOCK in actions
        assert RecommendationAction.MONITOR not in actions

    def test_no_conflict_across_different_targets(self) -> None:
        block = _rec(RecommendationAction.BLOCK, priority=100, target_value="1.1.1.1")
        monitor = _rec(RecommendationAction.MONITOR, priority=150, target_value="2.2.2.2")
        f = _finding({FindingCategory.MALICIOUS_INFRASTRUCTURE}, recommendations=(block, monitor))
        rollup = _engine().rollup([f])
        assert {r.action for r in rollup} == {
            RecommendationAction.BLOCK,
            RecommendationAction.MONITOR,
        }


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


class TestDeterminism:
    def test_repeated_rollup_identical(self) -> None:
        f = _finding({FindingCategory.VULNERABILITY}, Severity.CRITICAL, fid="fnd_1")
        engine = _engine()
        owned = engine.for_finding(f)
        enriched = f.model_copy(update={"recommendations": owned})
        assert engine.rollup([enriched]) == engine.rollup([enriched])


# --------------------------------------------------------------------------- #
# End-to-end via reason() / the offline pipeline
# --------------------------------------------------------------------------- #


class TestEndToEnd:
    def test_cve_recommends_patch(self) -> None:
        body = TestClient(app).post("/api/v1/investigate", json={"query": "CVE-2021-44228"}).json()
        summary = body["investigation_summary"]
        actions = {r["action"] for r in summary["recommendations"]}
        assert "patch_immediately" in actions

    def test_findings_own_their_recommendations(self) -> None:
        body = TestClient(app).post("/api/v1/investigate", json={"query": "CVE-2021-44228"}).json()
        findings = body["investigation_summary"]["findings"]
        vuln = next(f for f in findings if "vulnerability" in f["categories"])
        assert len(vuln["recommendations"]) >= 1
        # finding-owned recs carry no back-reference
        assert all(r["finding_ids"] == [] for r in vuln["recommendations"])

    def test_rollup_items_reference_findings(self) -> None:
        body = TestClient(app).post("/api/v1/investigate", json={"query": "CVE-2021-44228"}).json()
        rollup = body["investigation_summary"]["recommendations"]
        assert rollup  # non-empty
        assert all(len(r["finding_ids"]) >= 1 for r in rollup)

    def test_no_findings_no_recommendations(self) -> None:
        # Free text routes to no providers → no findings → no recommendations.
        body = TestClient(app).post(
            "/api/v1/investigate", json={"query": "zzznotarealindicator999"}
        ).json()
        summary = body["investigation_summary"]
        assert summary["findings"] == []
        assert summary["recommendations"] == []
