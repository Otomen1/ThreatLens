"""Deterministic builders for synthetic InvestigationSummary inputs.

The Timeline Engine consumes the Reasoning Engine's frozen
``InvestigationSummary`` — specifically
``Finding.evidence[].evidence.evidence.observed_at``. Mirrors
``tests/correlation/factories.py``'s shape for the parts it shares
(``finding``/``summary``) but adds evidence-with-timestamp support, which
the Timeline Engine needs and Correlation's factory does not.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import AttributedEvidence
from threatlens.providers.results import Evidence, EvidenceType
from threatlens.reasoning.models import (
    Confidence,
    ConfidenceBand,
    EvidenceDimension,
    EvidencePolarity,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
    WeightedEvidence,
)

NOW = datetime(2024, 1, 1, tzinfo=UTC)
_CONFIDENCE = Confidence(score=80, band=ConfidenceBand.HIGH)


def evidence(
    summary_text: str,
    observed_at: datetime | None,
    *,
    evidence_type: EvidenceType = EvidenceType.CLASSIFICATION,
    value: str | None = None,
    sources: Iterable[str] = ("test_provider",),
) -> WeightedEvidence:
    """Build a minimal ``WeightedEvidence`` wrapping one ``Evidence`` observation."""
    raw = Evidence(type=evidence_type, summary=summary_text, value=value, observed_at=observed_at)
    return WeightedEvidence(
        evidence=AttributedEvidence(evidence=raw, sources=list(sources)),
        weight=1.0,
        polarity=EvidencePolarity.SUPPORTING,
        dimension=EvidenceDimension.REPUTATION,
    )


def finding(
    fid: str,
    *,
    categories: Iterable[FindingCategory] = (FindingCategory.MALICIOUS_INFRASTRUCTURE,),
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "8.8.8.8",
    severity: Severity = Severity.HIGH,
    evidence_items: Iterable[WeightedEvidence] = (),
) -> Finding:
    """Build a minimal, valid :class:`Finding`, optionally carrying evidence."""
    return Finding(
        id=fid,
        title=f"{fid} title",
        categories=frozenset(categories),
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=_CONFIDENCE,
        evidence=list(evidence_items),
    )


def summary(
    findings: Iterable[Finding],
    *,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "8.8.8.8",
    engine_version: str = "1.0",
    generated_at: datetime = NOW,
) -> InvestigationSummary:
    """Build a minimal, valid :class:`InvestigationSummary` around ``findings``."""
    return InvestigationSummary(
        entity_type=entity_type,
        entity_value=entity_value,
        posture=Severity.HIGH,
        overall_confidence=_CONFIDENCE,
        categories=frozenset(),
        findings=list(findings),
        engine_version=engine_version,
        generated_at=generated_at,
    )
