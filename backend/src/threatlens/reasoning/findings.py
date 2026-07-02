"""The FindingEngine — deterministic finding generation, identity, and merge.

Runs each rule's predicate/effect over the assembled ledger, groups the drafts by
their merge key ``(subject_type, subject_value, primary_category)``, and builds
one :class:`Finding` per group: union of evidence/categories/rule_ids, highest
severity, attribution preserved, confidence scored by the existing
:class:`ConfidenceScorer` (unchanged), and a content-addressed identity.

Finding identity strategy (stable, deterministic):
    id = "fnd_" + sha256(primary_category | subject_type | subject_value |
                         sorted canonical evidence identities)[:16]
where a canonical evidence identity is ``"{type}:{value}"`` using the evidence's
canonical ``value`` only — never its free-text summary. The hash excludes
timestamps, wording, ordering (the identities are sorted), and AI. The same
evidence therefore always yields the same id.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime

from ..entities.models import Entity
from ..providers.aggregation import AttributedRelationship
from .confidence import ConfidenceScorer
from .evidence import EvidenceLedger
from .models import Finding, FindingCategory, Severity, WeightedEvidence
from .registry import RuleRegistry
from .rules import FindingDraft, RuleContext, etype, evalue

_MergeKey = tuple[str, str, str]  # (subject_type, subject_value, primary_category)


class FindingEngine:
    """Turns rule drafts into deterministic, scored, merged findings."""

    def __init__(self, registry: RuleRegistry, scorer: ConfidenceScorer | None = None) -> None:
        self._registry = registry
        self._scorer = scorer or ConfidenceScorer()

    def generate(self, entity: Entity, ledger: EvidenceLedger, *, now: datetime) -> list[Finding]:
        """Produce the deterministic, ordered list of findings for ``entity``."""
        ctx = RuleContext(entity=entity, ledger=ledger)
        drafts = [rule.effect(ctx) for rule in self._registry.rules if rule.predicate(ctx)]

        groups: dict[_MergeKey, list[FindingDraft]] = {}
        for draft in drafts:
            key = (
                draft.subject_type.value,
                draft.subject_value,
                draft.primary_category.value,
            )
            groups.setdefault(key, []).append(draft)

        findings = [self._build(groups[key], now=now) for key in sorted(groups)]
        # Highest severity first, then most confident, then stable id.
        findings.sort(key=lambda f: (-int(f.severity), -f.confidence.score, f.id))
        return findings

    def _build(self, group: list[FindingDraft], *, now: datetime) -> Finding:
        lead = min(group, key=lambda d: (-int(d.severity), d.rule_id))
        supporting = _dedupe_evidence(ev for draft in group for ev in draft.supporting)
        contradicting = _dedupe_evidence(ev for draft in group for ev in draft.contradicting)
        all_evidence = (*supporting, *contradicting)

        categories: frozenset[FindingCategory] = frozenset(
            cat for draft in group for cat in draft.categories
        )
        rule_ids = sorted({draft.rule_id for draft in group})
        severity = max(draft.severity for draft in group)
        relationships = _dedupe_relationships(rel for draft in group for rel in draft.relationships)
        sources = sorted({src for ev in all_evidence for src in ev.evidence.sources})
        confidence = self._scorer.score(all_evidence, now=now)
        finding_id = compute_finding_id(
            lead.primary_category, lead.subject_type.value, lead.subject_value, all_evidence
        )
        return Finding(
            id=finding_id,
            title=lead.title,
            categories=categories,
            subject_type=lead.subject_type,
            subject_value=lead.subject_value,
            severity=severity,
            confidence=confidence,
            priority=0,  # derived in 3.1d
            evidence=list(all_evidence),
            relationships=list(relationships),
            sources=sources,
            rationale=lead.rationale,
            rule_ids=rule_ids,
            recommendations=[],  # 3.1c
        )


# --------------------------------------------------------------------------- #
# Identity & de-duplication helpers
# --------------------------------------------------------------------------- #


def compute_finding_id(
    primary_category: FindingCategory,
    subject_type: str,
    subject_value: str,
    evidence: Iterable[WeightedEvidence],
) -> str:
    """Deterministic, content-addressed finding id (see module docstring)."""
    identities = sorted(
        {f"{etype(we).value}:{value.strip().lower()}" for we in evidence if (value := evalue(we))}
    )
    payload = "|".join(
        [primary_category.value, subject_type, subject_value.strip().lower(), *identities]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"fnd_{digest}"


def _evidence_key(we: WeightedEvidence) -> tuple[str, str, str, tuple[str, ...], str]:
    return (
        we.dimension.value,
        etype(we).value,
        evalue(we) or "",
        tuple(we.evidence.sources),
        we.polarity.value,
    )


def _dedupe_evidence(items: Iterable[WeightedEvidence]) -> tuple[WeightedEvidence, ...]:
    seen: set[tuple[str, str, str, tuple[str, ...], str]] = set()
    unique: list[WeightedEvidence] = []
    for we in items:
        key = _evidence_key(we)
        if key not in seen:
            seen.add(key)
            unique.append(we)
    return tuple(sorted(unique, key=_evidence_key))


def _relationship_key(rel: AttributedRelationship) -> tuple[str, str, str]:
    return (
        rel.relationship.relationship.value,
        rel.relationship.target_type.value,
        rel.relationship.target_value,
    )


def _dedupe_relationships(
    items: Iterable[AttributedRelationship],
) -> tuple[AttributedRelationship, ...]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[AttributedRelationship] = []
    for rel in items:
        key = _relationship_key(rel)
        if key not in seen:
            seen.add(key)
            unique.append(rel)
    return tuple(sorted(unique, key=_relationship_key))


def overall_posture(findings: list[Finding]) -> Severity:
    """The aggregate posture — the worst severity among findings."""
    if not findings:
        return Severity.INFORMATIONAL
    return max(f.severity for f in findings)
