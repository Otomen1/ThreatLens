"""Tests for the five Phase 3.1b finding rules (predicate + effect).

Each rule is exercised in isolation over synthetic rule contexts: it must fire
on the right signal, stay silent otherwise, and draft the correct category and
severity. Engine-level concerns (identity, merge, ordering) live in
test_finding_engine.py.
"""

from __future__ import annotations

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers.aggregation import AttributedEvidence, AttributedRelationship
from threatlens.providers.results import (
    Evidence,
    EvidenceType,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
)
from threatlens.reasoning import EvidenceLedger
from threatlens.reasoning.models import (
    EvidenceDimension,
    EvidencePolarity,
    FindingCategory,
    Severity,
    WeightedEvidence,
)
from threatlens.reasoning.rules import (
    AttackTechniqueRule,
    CriticalVulnerabilityRule,
    KnownMalwareRule,
    MaliciousInfrastructureRule,
    RuleContext,
    ThreatActorRule,
)


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
    etype: EvidenceType,
    *,
    value: str | None = None,
    sources: tuple[str, ...] = ("nvd",),
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTING,
    dimension: EvidenceDimension = EvidenceDimension.WEAKNESS,
    weight: float = 0.6,
) -> WeightedEvidence:
    return WeightedEvidence(
        evidence=AttributedEvidence(
            evidence=Evidence(type=etype, summary="s", value=value),
            sources=list(sources),
        ),
        weight=weight,
        polarity=polarity,
        dimension=dimension,
    )


def _rel(
    target_type: RelationshipTargetType,
    target_value: str,
    *,
    rel_type: RelationshipType = RelationshipType.RELATED_TO,
    sources: tuple[str, ...] = ("mitre_attack",),
) -> AttributedRelationship:
    return AttributedRelationship(
        relationship=Relationship(
            relationship=rel_type, target_type=target_type, target_value=target_value
        ),
        sources=list(sources),
    )


def _ledger(
    evidence: tuple[WeightedEvidence, ...] = (),
    relationships: tuple[AttributedRelationship, ...] = (),
) -> EvidenceLedger:
    return EvidenceLedger(evidence=evidence, relationships=relationships, references=())


def _ctx(entity: Entity, ledger: EvidenceLedger) -> RuleContext:
    return RuleContext(entity=entity, ledger=ledger)


# --------------------------------------------------------------------------- #
# Rule 1 — Critical Vulnerability
# --------------------------------------------------------------------------- #


class TestCriticalVulnerabilityRule:
    rule = CriticalVulnerabilityRule()

    def test_fires_for_critical_cve(self) -> None:
        ctx = _ctx(
            _entity(EntityType.CVE, "CVE-2021-44228"),
            _ledger((_we(EvidenceType.CATEGORY, value="CRITICAL"),)),
        )
        assert self.rule.predicate(ctx)
        draft = self.rule.effect(ctx)
        assert draft.severity is Severity.CRITICAL
        assert draft.primary_category is FindingCategory.VULNERABILITY
        assert FindingCategory.HIGH_PRIORITY in draft.categories

    def test_high_severity_is_high_not_critical(self) -> None:
        ctx = _ctx(
            _entity(EntityType.CVE, "CVE-2020-0001"),
            _ledger((_we(EvidenceType.CATEGORY, value="HIGH"),)),
        )
        draft = self.rule.effect(ctx)
        assert draft.severity is Severity.HIGH
        assert FindingCategory.HIGH_PRIORITY not in draft.categories

    def test_does_not_fire_for_medium_cve(self) -> None:
        ctx = _ctx(
            _entity(EntityType.CVE, "CVE-2020-0002"),
            _ledger((_we(EvidenceType.CATEGORY, value="MEDIUM"),)),
        )
        assert not self.rule.predicate(ctx)

    def test_does_not_fire_for_non_cve(self) -> None:
        ctx = _ctx(
            _entity(EntityType.IPV4, "1.2.3.4"),
            _ledger((_we(EvidenceType.CATEGORY, value="CRITICAL"),)),
        )
        assert not self.rule.predicate(ctx)


# --------------------------------------------------------------------------- #
# Rule 2 — Malicious Infrastructure
# --------------------------------------------------------------------------- #


class TestMaliciousInfrastructureRule:
    rule = MaliciousInfrastructureRule()

    def test_fires_for_malicious_ip(self) -> None:
        ctx = _ctx(
            _entity(EntityType.IPV4, "1.2.3.4"),
            _ledger(
                (
                    _we(
                        EvidenceType.OTHER,
                        value="malicious",
                        sources=("abuseipdb",),
                        polarity=EvidencePolarity.SUPPORTING,
                        dimension=EvidenceDimension.REPUTATION,
                    ),
                )
            ),
        )
        assert self.rule.predicate(ctx)
        draft = self.rule.effect(ctx)
        assert draft.primary_category is FindingCategory.MALICIOUS_INFRASTRUCTURE
        assert draft.severity is Severity.HIGH
        assert len(draft.supporting) == 1

    def test_includes_contradicting_reputation(self) -> None:
        ctx = _ctx(
            _entity(EntityType.DOMAIN, "evil.example.com"),
            _ledger(
                (
                    _we(
                        EvidenceType.OTHER,
                        value="malicious",
                        sources=("abuseipdb",),
                        dimension=EvidenceDimension.REPUTATION,
                    ),
                    _we(
                        EvidenceType.OTHER,
                        value="benign",
                        sources=("otx",),
                        polarity=EvidencePolarity.CONTRADICTING,
                        dimension=EvidenceDimension.REPUTATION,
                    ),
                )
            ),
        )
        draft = self.rule.effect(ctx)
        assert len(draft.supporting) == 1
        assert len(draft.contradicting) == 1

    def test_does_not_fire_without_reputation(self) -> None:
        ctx = _ctx(_entity(EntityType.IPV4, "1.2.3.4"), _ledger())
        assert not self.rule.predicate(ctx)

    def test_does_not_fire_for_non_ioc(self) -> None:
        ctx = _ctx(
            _entity(EntityType.CVE, "CVE-2021-44228"),
            _ledger(
                (
                    _we(
                        EvidenceType.OTHER,
                        value="malicious",
                        dimension=EvidenceDimension.REPUTATION,
                    ),
                )
            ),
        )
        assert not self.rule.predicate(ctx)


# --------------------------------------------------------------------------- #
# Rule 3 — Known Malware
# --------------------------------------------------------------------------- #


class TestKnownMalwareRule:
    rule = KnownMalwareRule()

    def test_fires_for_malware_family_entity(self) -> None:
        ctx = _ctx(
            _entity(EntityType.MALWARE_FAMILY, "Emotet"),
            _ledger((_we(EvidenceType.CLASSIFICATION, value="S0367", sources=("mitre_attack",)),)),
        )
        assert self.rule.predicate(ctx)
        assert self.rule.effect(ctx).primary_category is FindingCategory.MALWARE

    def test_fires_for_malware_evidence(self) -> None:
        ctx = _ctx(
            _entity(EntityType.SHA256, "abc"),
            _ledger(
                (_we(EvidenceType.MALWARE_FAMILY, value="Emotet", sources=("malwarebazaar",)),)
            ),
        )
        assert self.rule.predicate(ctx)

    def test_fires_for_malware_relationship(self) -> None:
        ctx = _ctx(
            _entity(EntityType.URL, "http://x"),
            _ledger(relationships=(_rel(RelationshipTargetType.MALWARE_FAMILY, "Emotet"),)),
        )
        assert self.rule.predicate(ctx)
        assert len(self.rule.effect(ctx).supporting) == 1

    def test_does_not_fire_without_malware(self) -> None:
        ctx = _ctx(_entity(EntityType.IPV4, "1.2.3.4"), _ledger())
        assert not self.rule.predicate(ctx)


# --------------------------------------------------------------------------- #
# Rule 4 — Threat Actor Intelligence
# --------------------------------------------------------------------------- #


class TestThreatActorRule:
    rule = ThreatActorRule()

    def test_fires_for_threat_actor_entity(self) -> None:
        ctx = _ctx(
            _entity(EntityType.THREAT_ACTOR, "APT28"),
            _ledger((_we(EvidenceType.CLASSIFICATION, value="G0007", sources=("mitre_attack",)),)),
        )
        assert self.rule.predicate(ctx)
        draft = self.rule.effect(ctx)
        assert draft.primary_category is FindingCategory.THREAT_ACTOR
        assert draft.severity is Severity.MEDIUM

    def test_fires_on_attributed_relationship(self) -> None:
        ctx = _ctx(
            _entity(EntityType.IPV4, "1.2.3.4"),
            _ledger(
                relationships=(
                    _rel(
                        RelationshipTargetType.THREAT_ACTOR,
                        "APT28",
                        rel_type=RelationshipType.ATTRIBUTED_TO,
                        sources=("otx",),
                    ),
                )
            ),
        )
        assert self.rule.predicate(ctx)
        assert len(self.rule.effect(ctx).supporting) == 1

    def test_does_not_fire_on_mere_association(self) -> None:
        ctx = _ctx(
            _entity(EntityType.MALWARE_FAMILY, "Emotet"),
            _ledger(
                relationships=(
                    _rel(
                        RelationshipTargetType.THREAT_ACTOR,
                        "APT28",
                        rel_type=RelationshipType.ASSOCIATED_WITH,
                    ),
                )
            ),
        )
        assert not self.rule.predicate(ctx)


# --------------------------------------------------------------------------- #
# Rule 5 — Observed Attack Technique
# --------------------------------------------------------------------------- #


class TestAttackTechniqueRule:
    rule = AttackTechniqueRule()

    def test_fires_for_technique_entity(self) -> None:
        ctx = _ctx(
            _entity(EntityType.MITRE_TECHNIQUE, "T1059"),
            _ledger((_we(EvidenceType.CLASSIFICATION, value="T1059", sources=("mitre_attack",)),)),
        )
        assert self.rule.predicate(ctx)
        draft = self.rule.effect(ctx)
        assert draft.primary_category is FindingCategory.ATTACK_PATTERN
        assert draft.severity is Severity.MEDIUM

    def test_fires_on_technique_relationship(self) -> None:
        ctx = _ctx(
            _entity(EntityType.MALWARE_FAMILY, "Emotet"),
            _ledger(relationships=(_rel(RelationshipTargetType.ATTACK_PATTERN, "T1059"),)),
        )
        assert self.rule.predicate(ctx)
        assert len(self.rule.effect(ctx).supporting) == 1

    def test_does_not_fire_without_technique(self) -> None:
        ctx = _ctx(_entity(EntityType.IPV4, "1.2.3.4"), _ledger())
        assert not self.rule.predicate(ctx)
