"""Deterministic quality and evidence-freshness assessment for detections."""

from __future__ import annotations

from datetime import datetime, timedelta

from ..entities.types import EntityType
from ..reasoning import Finding, InvestigationSummary
from .models import DetectionArtifact, DetectionFreshness, DetectionQuality
from .types import (
    DetectionFreshnessStatus,
    DetectionQualityBand,
    DetectionValidationLevel,
    DetectionValidationStatus,
)

_AGE_POLICY: dict[EntityType, tuple[int, int]] = {
    EntityType.IPV4: (30, 90),
    EntityType.IPV6: (30, 90),
    EntityType.DOMAIN: (30, 90),
    EntityType.URL: (14, 45),
    EntityType.MD5: (90, 365),
    EntityType.SHA1: (90, 365),
    EntityType.SHA256: (90, 365),
}


def assess_artifacts(
    artifacts: tuple[DetectionArtifact, ...], summary: InvestigationSummary
) -> tuple[DetectionArtifact, ...]:
    """Attach reproducible quality/freshness assessments to artifacts."""
    findings = {finding.id: finding for finding in summary.findings}
    return tuple(
        artifact.model_copy(
            update={
                "quality": _quality(artifact, findings),
                "freshness": _freshness(artifact, findings, summary.generated_at),
            }
        )
        for artifact in artifacts
    )


def _quality(
    artifact: DetectionArtifact, findings: dict[str, Finding]
) -> DetectionQuality:
    related = [findings[item] for item in artifact.source_finding_ids if item in findings]
    score = 100
    deductions: list[str] = []
    if not related:
        score -= 45
        deductions.append("No source finding is available.")
    else:
        confidence = max(item.confidence.score for item in related)
        if confidence < 40:
            score -= 30
            deductions.append("Source confidence is below 40.")
        elif confidence < 70:
            score -= 15
            deductions.append("Source confidence is below 70.")
        source_count = len({source for item in related for source in item.sources})
        if source_count < 2:
            score -= 15
            deductions.append("Only one provider supports the source finding.")
    if artifact.validation.status is DetectionValidationStatus.INVALID:
        score -= 60
        deductions.append("Rule validation failed.")
    elif artifact.validation.level in {
        DetectionValidationLevel.STRUCTURAL,
        DetectionValidationLevel.UNAVAILABLE,
    }:
        score -= 10
        deductions.append("Only structural validation is available.")
    if artifact.metadata.get("mapping_profile", "").lower().startswith("generic"):
        score -= 10
        deductions.append("A generic field mapping is selected.")
    if artifact.metadata.get("excluded") == "true":
        score = 0
        deductions.append("The analyst excluded this rule.")
    score = max(0, min(score, 100))
    if score >= 80:
        band = DetectionQualityBand.STRONG
    elif score >= 60:
        band = DetectionQualityBand.REVIEW
    elif score >= 40:
        band = DetectionQualityBand.WEAK
    else:
        band = DetectionQualityBand.DO_NOT_DEPLOY
    return DetectionQuality(score=score, band=band, deductions=tuple(deductions))


def _freshness(
    artifact: DetectionArtifact,
    findings: dict[str, Finding],
    generated_at: datetime,
) -> DetectionFreshness:
    related = [findings[item] for item in artifact.source_finding_ids if item in findings]
    observed = [
        weighted.evidence.evidence.observed_at
        for finding in related
        for weighted in finding.evidence
        if weighted.evidence.evidence.observed_at is not None
    ]
    if not observed:
        return DetectionFreshness()
    latest = max(observed)
    entity_type = related[0].subject_type if related else EntityType.UNKNOWN
    policy = _AGE_POLICY.get(entity_type)
    if policy is None:
        return DetectionFreshness(
            status=DetectionFreshnessStatus.FRESH,
            last_evidence_at=latest,
        )
    review_after = latest + timedelta(days=policy[0])
    expires_at = latest + timedelta(days=policy[1])
    if generated_at >= expires_at:
        status = DetectionFreshnessStatus.EXPIRED
    elif generated_at >= review_after:
        status = DetectionFreshnessStatus.REVIEW_DUE
    else:
        status = DetectionFreshnessStatus.FRESH
    return DetectionFreshness(
        status=status,
        last_evidence_at=latest,
        review_after=review_after,
        expires_at=expires_at,
    )
