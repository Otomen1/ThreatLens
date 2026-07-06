"""Deterministic builders for synthetic InvestigationSummary inputs.

The Correlation Engine consumes the Reasoning Engine's frozen
``InvestigationSummary``; these helpers build minimal, valid summaries/findings
at a fixed timestamp so every correlation test is offline and reproducible.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from threatlens.entities.types import EntityType
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


def finding(
    fid: str,
    categories: Iterable[FindingCategory],
    *,
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "8.8.8.8",
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Build a minimal, valid :class:`Finding` carrying ``categories``."""
    return Finding(
        id=fid,
        title=f"{fid} title",
        categories=frozenset(categories),
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=_CONFIDENCE,
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
