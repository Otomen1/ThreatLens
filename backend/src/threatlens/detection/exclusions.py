"""Analyst-controlled false-positive exclusion primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ..reasoning import Finding, InvestigationSummary


@dataclass(frozen=True)
class DetectionExclusion:
    """An explicit exclusion for a finding subject.

    Exclusions are exact-match and case-insensitive by design. Wildcards are
    intentionally not supported here; broad exclusions should be represented
    by a reviewed, expiring rule in a higher-level policy layer.
    """

    subject_type: str
    subject_value: str
    reason: str
    expires_at: datetime | None = None

    def matches(self, finding: Finding, *, now: datetime | None = None) -> bool:
        if finding.subject_type.value.lower() != self.subject_type.strip().lower():
            return False
        if finding.subject_value.strip().lower() != self.subject_value.strip().lower():
            return False
        moment = now or datetime.now(UTC)
        return self.expires_at is None or self.expires_at > moment


def apply_exclusions(
    summary: InvestigationSummary,
    exclusions: tuple[DetectionExclusion, ...],
    *,
    now: datetime | None = None,
) -> InvestigationSummary:
    """Return a summary with only explicitly excluded detection subjects removed."""
    if not exclusions:
        return summary
    findings = tuple(
        finding
        for finding in summary.findings
        if not any(exclusion.matches(finding, now=now) for exclusion in exclusions)
    )
    return summary.model_copy(update={"findings": findings})
