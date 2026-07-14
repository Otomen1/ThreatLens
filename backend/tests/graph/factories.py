"""Deterministic builders for synthetic InvestigationSummary/CorrelationSummary inputs.

The Graph Engine consumes the Reasoning Engine's frozen ``InvestigationSummary``
and the Correlation Engine's frozen ``CorrelationSummary``. Mirrors
``tests/timeline/factories.py``'s shape for the parts it shares
(``finding``/``summary``) but adds relationship support (finding-level edges)
and ``CorrelationObservation``/``CorrelationSummary`` builders
(correlation-level edges), which the Graph Engine needs and Timeline's
factory does not.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from threatlens.correlation.models import (
    CorrelationCategory,
    CorrelationEvidence,
    CorrelationMetadata,
    CorrelationObservation,
    CorrelationRelationship,
    CorrelationRelationshipType,
    CorrelationStatistics,
    CorrelationSummary,
)
from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import AttributedRelationship
from threatlens.providers.results import Relationship, RelationshipTargetType, RelationshipType
from threatlens.reasoning.models import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
)

NOW = datetime(2024, 1, 1, tzinfo=UTC)
_CONFIDENCE = Confidence(score=80, band=ConfidenceBand.HIGH)


def relationship(
    *,
    verb: RelationshipType = RelationshipType.ASSOCIATED_WITH,
    target_type: RelationshipTargetType = RelationshipTargetType.MALWARE_FAMILY,
    target_value: str = "Emotet",
    description: str | None = "test relationship",
    sources: Iterable[str] = ("test_provider",),
) -> AttributedRelationship:
    """Build a minimal ``AttributedRelationship`` wrapping one ``Relationship``."""
    return AttributedRelationship(
        relationship=Relationship(
            relationship=verb,
            target_type=target_type,
            target_value=target_value,
            description=description,
        ),
        sources=list(sources),
    )


def finding(
    fid: str,
    *,
    categories: Iterable[FindingCategory] = (FindingCategory.MALICIOUS_INFRASTRUCTURE,),
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "8.8.8.8",
    severity: Severity = Severity.HIGH,
    relationships: Iterable[AttributedRelationship] = (),
) -> Finding:
    """Build a minimal, valid :class:`Finding`, optionally carrying relationships."""
    return Finding(
        id=fid,
        title=f"{fid} title",
        categories=frozenset(categories),
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=_CONFIDENCE,
        relationships=list(relationships),
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


def correlation_evidence(
    finding_id: str,
    *,
    matched_category: FindingCategory = FindingCategory.MALICIOUS_INFRASTRUCTURE,
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "8.8.8.8",
    summary_text: str = "matched",
) -> CorrelationEvidence:
    """Build a minimal :class:`CorrelationEvidence` citation."""
    return CorrelationEvidence(
        finding_id=finding_id,
        matched_category=matched_category,
        subject_type=subject_type,
        subject_value=subject_value,
        summary=summary_text,
    )


def correlation_relationship(
    *,
    source_finding_id: str,
    target_finding_id: str,
    rel_type: CorrelationRelationshipType = CorrelationRelationshipType.CO_OCCURS_WITH,
    description: str = "test correlation relationship",
) -> CorrelationRelationship:
    """Build a minimal :class:`CorrelationRelationship` between two finding ids."""
    return CorrelationRelationship(
        type=rel_type,
        source_finding_id=source_finding_id,
        target_finding_id=target_finding_id,
        description=description,
    )


def observation(
    obs_id: str,
    *,
    rule_id: str = "test_rule",
    category: CorrelationCategory = CorrelationCategory.MALICIOUS_EXPOSED_INFRASTRUCTURE,
    title: str = "Test observation",
    evidence_items: Iterable[CorrelationEvidence] = (),
    relationships: Iterable[CorrelationRelationship] = (),
) -> CorrelationObservation:
    """Build a minimal, valid :class:`CorrelationObservation`.

    ``source_finding_ids`` is derived from ``evidence_items`` exactly like the
    real engine (``correlation/engine.py::_build_observation``) derives it —
    never supplied independently, so a test can never construct an internally
    inconsistent observation by accident.
    """
    items = list(evidence_items)
    return CorrelationObservation(
        id=obs_id,
        rule_id=rule_id,
        category=category,
        title=title,
        subject_type=items[0].subject_type if items else EntityType.IPV4,
        subject_value=items[0].subject_value if items else "8.8.8.8",
        evidence=tuple(items),
        relationships=tuple(relationships),
        source_finding_ids=tuple(sorted({e.finding_id for e in items})),
    )


def correlation_summary(
    observations: Iterable[CorrelationObservation],
    *,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "8.8.8.8",
    generated_at: datetime = NOW,
) -> CorrelationSummary:
    """Build a minimal, valid :class:`CorrelationSummary` around ``observations``."""
    items = list(observations)
    return CorrelationSummary(
        id="cor_test_summary",
        entity_type=entity_type,
        entity_value=entity_value,
        observations=tuple(items),
        matches=(),
        statistics=CorrelationStatistics(total_observations=len(items)),
        metadata=CorrelationMetadata(
            entity_type=entity_type,
            entity_value=entity_value,
            generated_at=generated_at,
            framework_version="test",
            source_engine_version="test",
        ),
        source_finding_ids=(),
    )
