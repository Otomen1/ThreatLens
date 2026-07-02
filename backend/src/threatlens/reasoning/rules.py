"""Finding rules — the typed, deterministic rule set (Phase 3.1b).

A rule is a small Python object declaring ``id``/``version``/``category``/
``default_severity`` plus a pure ``predicate`` (does it fire?) and ``effect``
(what finding does it draft?). There is no DSL and no external rule format — rules
are code, type-checked and unit-tested alongside everything else.

Each effect returns a :class:`FindingDraft`: the supporting (and any
contradicting) evidence for *its* claim, plus categories/severity/rationale. The
:class:`~threatlens.reasoning.findings.FindingEngine` turns drafts into findings,
scoring confidence and merging duplicates.

Phase 3.1b ships exactly five validation rules; no more.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from ..entities.models import Entity
from ..entities.types import EntityType
from ..providers.aggregation import AttributedEvidence, AttributedRelationship
from ..providers.results import (
    Evidence,
    EvidenceType,
    RelationshipTargetType,
    RelationshipType,
)
from . import config
from .evidence import EvidenceLedger
from .models import (
    EvidenceDimension,
    EvidencePolarity,
    FindingCategory,
    Severity,
    WeightedEvidence,
)

# --------------------------------------------------------------------------- #
# Rule inputs/outputs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RuleContext:
    """Everything a rule reasons over: the entity and its assembled ledger."""

    entity: Entity
    ledger: EvidenceLedger


@dataclass(frozen=True)
class FindingDraft:
    """A rule's proposed finding before scoring, identity, and merge."""

    rule_id: str
    primary_category: FindingCategory
    categories: frozenset[FindingCategory]
    severity: Severity
    subject_type: EntityType
    subject_value: str
    title: str
    rationale: str
    supporting: tuple[WeightedEvidence, ...]
    contradicting: tuple[WeightedEvidence, ...]
    relationships: tuple[AttributedRelationship, ...]


class FindingRule(ABC):
    """Base class for deterministic finding rules."""

    id: ClassVar[str]
    version: ClassVar[str]
    category: ClassVar[FindingCategory]
    default_severity: ClassVar[Severity]

    @abstractmethod
    def predicate(self, ctx: RuleContext) -> bool:
        """True if this rule fires for ``ctx`` (pure, no side effects)."""

    @abstractmethod
    def effect(self, ctx: RuleContext) -> FindingDraft:
        """Draft the finding. Only called when :meth:`predicate` is True."""


# --------------------------------------------------------------------------- #
# Shared evidence accessors / helpers
# --------------------------------------------------------------------------- #


def etype(we: WeightedEvidence) -> EvidenceType:
    """The underlying evidence type of a weighted item."""
    return we.evidence.evidence.type


def evalue(we: WeightedEvidence) -> str | None:
    """The underlying canonical value of a weighted item (may be None)."""
    return we.evidence.evidence.value


def _as_supporting(we: WeightedEvidence) -> WeightedEvidence:
    """Recast evidence as SUPPORTING for the claim of the finding citing it."""
    if we.polarity is EvidencePolarity.SUPPORTING:
        return we
    return we.model_copy(update={"polarity": EvidencePolarity.SUPPORTING})


def _relationship_evidence(
    rel: AttributedRelationship, dimension: EvidenceDimension, summary: str
) -> WeightedEvidence:
    """Lift a signal-bearing relationship into supporting weighted evidence."""
    sources = list(rel.sources)
    weight = max(0.0, min(1.0, config.max_authority(sources)))
    return WeightedEvidence(
        evidence=AttributedEvidence(
            evidence=Evidence(
                type=EvidenceType.OTHER,
                summary=summary,
                value=rel.relationship.target_value,
            ),
            sources=sources,
        ),
        weight=weight,
        polarity=EvidencePolarity.SUPPORTING,
        dimension=dimension,
    )


_KNOWLEDGE_TYPES = (EvidenceType.CLASSIFICATION, EvidenceType.CATEGORY, EvidenceType.TAG)


# --------------------------------------------------------------------------- #
# Rule 1 — Critical Vulnerability
# --------------------------------------------------------------------------- #


class CriticalVulnerabilityRule(FindingRule):
    """High/critical-severity CVE knowledge → a Vulnerability finding."""

    id = "vuln.critical"
    version = "1"
    category = FindingCategory.VULNERABILITY
    default_severity = Severity.HIGH

    @staticmethod
    def _severity_label(we: WeightedEvidence) -> str | None:
        value = evalue(we)
        if etype(we) is EvidenceType.CATEGORY and value:
            upper = value.upper()
            if upper in ("HIGH", "CRITICAL"):
                return upper
        return None

    def predicate(self, ctx: RuleContext) -> bool:
        if ctx.entity.type is not EntityType.CVE:
            return False
        return any(self._severity_label(we) for we in ctx.ledger.evidence)

    def effect(self, ctx: RuleContext) -> FindingDraft:
        labels = {self._severity_label(we) for we in ctx.ledger.evidence}
        is_critical = "CRITICAL" in labels
        severity = Severity.CRITICAL if is_critical else Severity.HIGH
        categories = {FindingCategory.VULNERABILITY}
        if is_critical:
            categories.add(FindingCategory.HIGH_PRIORITY)
        supporting = tuple(_as_supporting(we) for we in ctx.ledger.evidence)
        label = "Critical" if is_critical else "High-severity"
        return FindingDraft(
            rule_id=self.id,
            primary_category=self.category,
            categories=frozenset(categories),
            severity=severity,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title=f"{label} vulnerability: {ctx.entity.value}",
            rationale=(
                f"{ctx.entity.value} carries a {severity.name.lower()} severity rating "
                "from authoritative vulnerability data."
            ),
            supporting=supporting,
            contradicting=(),
            relationships=(),
        )


# --------------------------------------------------------------------------- #
# Rule 2 — Malicious Infrastructure
# --------------------------------------------------------------------------- #


class MaliciousInfrastructureRule(FindingRule):
    """High-confidence malicious reputation on an IOC → a Malicious Infra finding."""

    id = "infra.malicious"
    version = "1"
    category = FindingCategory.MALICIOUS_INFRASTRUCTURE
    default_severity = Severity.HIGH

    _APPLIES: ClassVar[frozenset[EntityType]] = frozenset(
        {EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN, EntityType.URL}
    )

    @staticmethod
    def _reputation(ledger: EvidenceLedger) -> list[WeightedEvidence]:
        return [we for we in ledger.evidence if we.dimension is EvidenceDimension.REPUTATION]

    def predicate(self, ctx: RuleContext) -> bool:
        if ctx.entity.type not in self._APPLIES:
            return False
        return any(
            we.polarity is EvidencePolarity.SUPPORTING for we in self._reputation(ctx.ledger)
        )

    def effect(self, ctx: RuleContext) -> FindingDraft:
        reputation = self._reputation(ctx.ledger)
        supporting = tuple(we for we in reputation if we.polarity is EvidencePolarity.SUPPORTING)
        contradicting = tuple(
            we for we in reputation if we.polarity is EvidencePolarity.CONTRADICTING
        )
        return FindingDraft(
            rule_id=self.id,
            primary_category=self.category,
            categories=frozenset({FindingCategory.MALICIOUS_INFRASTRUCTURE}),
            severity=Severity.HIGH,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title=f"Malicious infrastructure: {ctx.entity.value}",
            rationale=(
                f"{ctx.entity.value} is reported as malicious by threat-intelligence sources."
            ),
            supporting=supporting,
            contradicting=contradicting,
            relationships=(),
        )


# --------------------------------------------------------------------------- #
# Rule 3 — Known Malware
# --------------------------------------------------------------------------- #


class KnownMalwareRule(FindingRule):
    """Malware evidence / association → a Known Malware finding."""

    id = "malware.known"
    version = "1"
    category = FindingCategory.MALWARE
    default_severity = Severity.HIGH

    @staticmethod
    def _malware_evidence(ledger: EvidenceLedger) -> list[WeightedEvidence]:
        return [we for we in ledger.evidence if etype(we) is EvidenceType.MALWARE_FAMILY]

    @staticmethod
    def _malware_relationships(ledger: EvidenceLedger) -> list[AttributedRelationship]:
        return [
            rel
            for rel in ledger.relationships
            if rel.relationship.target_type is RelationshipTargetType.MALWARE_FAMILY
        ]

    def predicate(self, ctx: RuleContext) -> bool:
        return (
            ctx.entity.type is EntityType.MALWARE_FAMILY
            or bool(self._malware_evidence(ctx.ledger))
            or bool(self._malware_relationships(ctx.ledger))
        )

    def effect(self, ctx: RuleContext) -> FindingDraft:
        supporting = [_as_supporting(we) for we in self._malware_evidence(ctx.ledger)]
        relationships = tuple(self._malware_relationships(ctx.ledger))
        supporting.extend(
            _relationship_evidence(
                rel,
                EvidenceDimension.CAPABILITY,
                f"Associated malware: {rel.relationship.target_value}",
            )
            for rel in relationships
        )
        if ctx.entity.type is EntityType.MALWARE_FAMILY:
            supporting.extend(
                _as_supporting(we) for we in ctx.ledger.evidence if etype(we) in _KNOWLEDGE_TYPES
            )
        return FindingDraft(
            rule_id=self.id,
            primary_category=self.category,
            categories=frozenset({FindingCategory.MALWARE}),
            severity=Severity.HIGH,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title=f"Known malware: {ctx.entity.value}",
            rationale=f"{ctx.entity.value} is associated with known malware.",
            supporting=tuple(supporting),
            contradicting=(),
            relationships=relationships,
        )


# --------------------------------------------------------------------------- #
# Rule 4 — Threat Actor Intelligence
# --------------------------------------------------------------------------- #


class ThreatActorRule(FindingRule):
    """Threat-actor knowledge or attribution → a Threat Actor finding."""

    id = "actor.attributed"
    version = "1"
    category = FindingCategory.THREAT_ACTOR
    default_severity = Severity.MEDIUM

    @staticmethod
    def _attribution(ledger: EvidenceLedger) -> list[AttributedRelationship]:
        return [
            rel
            for rel in ledger.relationships
            if rel.relationship.target_type is RelationshipTargetType.THREAT_ACTOR
            and rel.relationship.relationship is RelationshipType.ATTRIBUTED_TO
        ]

    def predicate(self, ctx: RuleContext) -> bool:
        return ctx.entity.type is EntityType.THREAT_ACTOR or bool(self._attribution(ctx.ledger))

    def effect(self, ctx: RuleContext) -> FindingDraft:
        supporting: list[WeightedEvidence] = []
        if ctx.entity.type is EntityType.THREAT_ACTOR:
            supporting.extend(
                _as_supporting(we) for we in ctx.ledger.evidence if etype(we) in _KNOWLEDGE_TYPES
            )
        relationships = tuple(self._attribution(ctx.ledger))
        supporting.extend(
            _relationship_evidence(
                rel, EvidenceDimension.ATTRIBUTION, f"Attributed to {rel.relationship.target_value}"
            )
            for rel in relationships
        )
        return FindingDraft(
            rule_id=self.id,
            primary_category=self.category,
            categories=frozenset({FindingCategory.THREAT_ACTOR}),
            severity=Severity.MEDIUM,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title=f"Threat actor intelligence: {ctx.entity.value}",
            rationale=(
                f"Activity related to {ctx.entity.value} is associated with a known threat actor."
            ),
            supporting=tuple(supporting),
            contradicting=(),
            relationships=relationships,
        )


# --------------------------------------------------------------------------- #
# Rule 5 — Observed Attack Technique
# --------------------------------------------------------------------------- #


class AttackTechniqueRule(FindingRule):
    """ATT&CK technique knowledge or usage → an Attack Technique finding."""

    id = "attack.technique"
    version = "1"
    category = FindingCategory.ATTACK_PATTERN
    default_severity = Severity.MEDIUM

    @staticmethod
    def _techniques(ledger: EvidenceLedger) -> list[AttributedRelationship]:
        return [
            rel
            for rel in ledger.relationships
            if rel.relationship.target_type is RelationshipTargetType.ATTACK_PATTERN
        ]

    def predicate(self, ctx: RuleContext) -> bool:
        return ctx.entity.type is EntityType.MITRE_TECHNIQUE or bool(self._techniques(ctx.ledger))

    def effect(self, ctx: RuleContext) -> FindingDraft:
        supporting: list[WeightedEvidence] = []
        if ctx.entity.type is EntityType.MITRE_TECHNIQUE:
            supporting.extend(
                _as_supporting(we)
                for we in ctx.ledger.evidence
                if etype(we) in (EvidenceType.CLASSIFICATION, EvidenceType.CATEGORY)
            )
        relationships = tuple(self._techniques(ctx.ledger))
        supporting.extend(
            _relationship_evidence(
                rel, EvidenceDimension.CAPABILITY, f"Uses technique {rel.relationship.target_value}"
            )
            for rel in relationships
        )
        return FindingDraft(
            rule_id=self.id,
            primary_category=self.category,
            categories=frozenset({FindingCategory.ATTACK_PATTERN}),
            severity=Severity.MEDIUM,
            subject_type=ctx.entity.type,
            subject_value=ctx.entity.value,
            title=f"Observed attack technique: {ctx.entity.value}",
            rationale=f"{ctx.entity.value} relates to known ATT&CK attack techniques.",
            supporting=tuple(supporting),
            contradicting=(),
            relationships=relationships,
        )


# The five validation rules. No more (Phase 3.1b).
DEFAULT_FINDING_RULES: tuple[type[FindingRule], ...] = (
    CriticalVulnerabilityRule,
    MaliciousInfrastructureRule,
    KnownMalwareRule,
    ThreatActorRule,
    AttackTechniqueRule,
)
