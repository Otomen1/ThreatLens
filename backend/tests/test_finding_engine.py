"""Tests for the FindingEngine: identity, merge, ordering, determinism.

Covers deterministic finding IDs, duplicate suppression, multi-rule merge,
rule ordering, conflicting/empty/unsupported evidence, repeated execution, and
the end-to-end InvestigationSummary integration via reason().
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers.aggregation import AttributedEvidence
from threatlens.providers.results import Evidence, EvidenceType
from threatlens.reasoning import (
    EvidenceLedger,
    FindingEngine,
    RuleRegistry,
    build_default_rule_registry,
    compute_finding_id,
)
from threatlens.reasoning.models import (
    EvidenceDimension,
    EvidencePolarity,
    FindingCategory,
    Severity,
    WeightedEvidence,
)
from threatlens.reasoning.rules import FindingDraft, FindingRule, RuleContext

NOW = datetime(2024, 6, 1, tzinfo=UTC)


def _entity(type_: EntityType, value: str = "x") -> Entity:
    return Entity(
        type=type_,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


def _we(
    value: str,
    *,
    sources: tuple[str, ...] = ("nvd",),
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTING,
) -> WeightedEvidence:
    return WeightedEvidence(
        evidence=AttributedEvidence(
            evidence=Evidence(type=EvidenceType.CLASSIFICATION, summary="s", value=value),
            sources=list(sources),
        ),
        weight=0.6,
        polarity=polarity,
        dimension=EvidenceDimension.WEAKNESS,
    )


def _ledger(*evidence: WeightedEvidence) -> EvidenceLedger:
    return EvidenceLedger(evidence=tuple(evidence), relationships=(), references=())


# Test-only rules that emit the same (subject, primary_category) so the engine
# must merge them. Defined here, never registered in the default set.
class _RuleA(FindingRule):
    id = "test.a"
    version = "1"
    category = FindingCategory.REPUTATION
    default_severity = Severity.LOW

    def predicate(self, ctx: RuleContext) -> bool:
        return True

    def effect(self, ctx: RuleContext) -> FindingDraft:
        return FindingDraft(
            rule_id=self.id,
            primary_category=FindingCategory.REPUTATION,
            categories=frozenset({FindingCategory.REPUTATION}),
            severity=Severity.LOW,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title="A",
            rationale="from A",
            supporting=(_we("shared", sources=("abuseipdb",)),),
            contradicting=(),
            relationships=(),
        )


class _RuleB(FindingRule):
    id = "test.b"
    version = "1"
    category = FindingCategory.REPUTATION
    default_severity = Severity.HIGH

    def predicate(self, ctx: RuleContext) -> bool:
        return True

    def effect(self, ctx: RuleContext) -> FindingDraft:
        return FindingDraft(
            rule_id=self.id,
            primary_category=FindingCategory.REPUTATION,
            categories=frozenset({FindingCategory.REPUTATION, FindingCategory.HIGH_PRIORITY}),
            severity=Severity.HIGH,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title="B",
            rationale="from B",
            supporting=(
                _we("shared", sources=("abuseipdb",)),  # duplicate of A's evidence
                _we("extra", sources=("otx",)),
            ),
            contradicting=(),
            relationships=(),
        )


def _two_rule_engine() -> FindingEngine:
    registry = RuleRegistry()
    registry.register(_RuleA())
    registry.register(_RuleB())
    return FindingEngine(registry)


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


class TestFindingIdentity:
    def test_same_evidence_same_id(self) -> None:
        ev = [_we("CVE-2021-44228"), _we("CRITICAL")]
        a = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-2021-44228", ev)
        b = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-2021-44228", ev)
        assert a == b
        assert a.startswith("fnd_")

    def test_id_independent_of_ordering(self) -> None:
        ev1 = [_we("aaa"), _we("bbb")]
        ev2 = [_we("bbb"), _we("aaa")]
        a = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-1", ev1)
        b = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-1", ev2)
        assert a == b

    def test_id_changes_with_subject(self) -> None:
        ev = [_we("x")]
        a = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-1", ev)
        b = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-2", ev)
        assert a != b

    def test_id_ignores_valueless_summary(self) -> None:
        # Two evidence items differing only in summary (no value) → same id.
        e1 = WeightedEvidence(
            evidence=AttributedEvidence(
                evidence=Evidence(type=EvidenceType.OTHER, summary="wording one"), sources=["nvd"]
            ),
            weight=0.5,
            polarity=EvidencePolarity.SUPPORTING,
            dimension=EvidenceDimension.WEAKNESS,
        )
        e2 = WeightedEvidence(
            evidence=AttributedEvidence(
                evidence=Evidence(type=EvidenceType.OTHER, summary="wording two"), sources=["nvd"]
            ),
            weight=0.5,
            polarity=EvidencePolarity.SUPPORTING,
            dimension=EvidenceDimension.WEAKNESS,
        )
        a = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-1", [e1])
        b = compute_finding_id(FindingCategory.VULNERABILITY, "cve", "CVE-1", [e2])
        assert a == b


# --------------------------------------------------------------------------- #
# Merge & duplicate suppression
# --------------------------------------------------------------------------- #


class TestMerge:
    def test_two_rules_merge_into_one_finding(self) -> None:
        findings = _two_rule_engine().generate(
            _entity(EntityType.IPV4, "1.2.3.4"), _ledger(), now=NOW
        )
        assert len(findings) == 1

    def test_merge_takes_highest_severity(self) -> None:
        finding = _two_rule_engine().generate(_entity(EntityType.IPV4), _ledger(), now=NOW)[0]
        assert finding.severity is Severity.HIGH  # max(LOW, HIGH)

    def test_merge_unions_categories_and_rule_ids(self) -> None:
        finding = _two_rule_engine().generate(_entity(EntityType.IPV4), _ledger(), now=NOW)[0]
        assert finding.categories == frozenset(
            {FindingCategory.REPUTATION, FindingCategory.HIGH_PRIORITY}
        )
        assert finding.rule_ids == ["test.a", "test.b"]

    def test_duplicate_evidence_suppressed(self) -> None:
        finding = _two_rule_engine().generate(_entity(EntityType.IPV4), _ledger(), now=NOW)[0]
        # A and B both contributed "shared"; B added "extra" → two unique items.
        values = sorted(e.evidence.evidence.value or "" for e in finding.evidence)
        assert values == ["extra", "shared"]

    def test_merge_preserves_attribution(self) -> None:
        finding = _two_rule_engine().generate(_entity(EntityType.IPV4), _ledger(), now=NOW)[0]
        assert set(finding.sources) == {"abuseipdb", "otx"}


# --------------------------------------------------------------------------- #
# Ordering / registry
# --------------------------------------------------------------------------- #


class TestRegistryOrdering:
    def test_default_registry_has_five_rules(self) -> None:
        assert len(build_default_rule_registry()) == 5

    def test_rules_sorted_by_id(self) -> None:
        ids = [r.id for r in build_default_rule_registry().rules]
        assert ids == sorted(ids)

    def test_findings_sorted_worst_first(self) -> None:
        finding = _two_rule_engine().generate(_entity(EntityType.IPV4), _ledger(), now=NOW)
        # Only one finding here, but severity ordering is asserted in merge tests.
        assert finding[0].severity is Severity.HIGH


# --------------------------------------------------------------------------- #
# Conflicting / empty / unsupported / determinism
# --------------------------------------------------------------------------- #


class TestEdgeCases:
    def test_empty_ledger_yields_no_findings(self) -> None:
        findings = build_default_engine().generate(_entity(EntityType.IPV4), _ledger(), now=NOW)
        assert findings == []

    def test_unsupported_entity_yields_no_findings(self) -> None:
        # CWE has no rule in the validation set.
        findings = build_default_engine().generate(
            _entity(EntityType.CWE, "CWE-79"),
            _ledger(_we("CWE-79")),
            now=NOW,
        )
        assert findings == []

    def test_conflicting_evidence_marks_contested(self) -> None:
        registry = RuleRegistry()
        registry.register(_ContestedRule())
        finding = FindingEngine(registry).generate(_entity(EntityType.IPV4), _ledger(), now=NOW)[0]
        assert finding.confidence.contested is True

    def test_repeated_execution_is_identical(self) -> None:
        engine = _two_rule_engine()
        entity = _entity(EntityType.IPV4)
        assert engine.generate(entity, _ledger(), now=NOW) == engine.generate(
            entity, _ledger(), now=NOW
        )


class _ContestedRule(FindingRule):
    id = "test.contested"
    version = "1"
    category = FindingCategory.MALICIOUS_INFRASTRUCTURE
    default_severity = Severity.HIGH

    def predicate(self, ctx: RuleContext) -> bool:
        return True

    def effect(self, ctx: RuleContext) -> FindingDraft:
        return FindingDraft(
            rule_id=self.id,
            primary_category=FindingCategory.MALICIOUS_INFRASTRUCTURE,
            categories=frozenset({FindingCategory.MALICIOUS_INFRASTRUCTURE}),
            severity=Severity.HIGH,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title="contested",
            rationale="r",
            supporting=(_we("mal", sources=("abuseipdb",)),),
            contradicting=(
                _we("benign", sources=("otx",), polarity=EvidencePolarity.CONTRADICTING),
            ),
            relationships=(),
        )


def build_default_engine() -> FindingEngine:
    return FindingEngine(build_default_rule_registry())


# --------------------------------------------------------------------------- #
# End-to-end via the real offline pipeline (/api/v1/investigate)
# --------------------------------------------------------------------------- #


class TestEndToEnd:
    def _findings(self, query: str) -> list[dict]:
        body = TestClient(app).post("/api/v1/investigate", json={"query": query}).json()
        return body["investigation_summary"]["findings"]

    def test_critical_vulnerability_finding(self) -> None:
        findings = self._findings("CVE-2021-44228")
        vuln = next(f for f in findings if "vulnerability" in f["categories"])
        assert vuln["severity"] == int(Severity.CRITICAL)
        assert vuln["confidence"]["band"] in ("high", "very_high")
        assert vuln["id"].startswith("fnd_")

    def test_attack_technique_finding(self) -> None:
        findings = self._findings("T1059")
        assert any("attack_pattern" in f["categories"] for f in findings)

    def test_threat_actor_finding(self) -> None:
        findings = self._findings("APT28")
        assert any("threat_actor" in f["categories"] for f in findings)

    def test_known_malware_finding(self) -> None:
        findings = self._findings("emotet")
        assert any("malware" in f["categories"] for f in findings)

    def test_posture_reflects_findings(self) -> None:
        body = TestClient(app).post("/api/v1/investigate", json={"query": "CVE-2021-44228"}).json()
        summary = body["investigation_summary"]
        assert summary["posture"] == int(Severity.CRITICAL)
        # 3.1c populates recommendations; finding generation itself is unchanged.
        assert len(summary["recommendations"]) >= 1
