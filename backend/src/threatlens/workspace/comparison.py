"""Deterministic comparison of two saved investigation snapshots."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .models import WorkspaceInvestigation


class FindingChange(BaseModel):
    model_config = ConfigDict(frozen=True)
    finding_id: str
    title: str
    severity_before: int | None = None
    severity_after: int | None = None
    change: str


class InvestigationComparison(BaseModel):
    model_config = ConfigDict(frozen=True)
    before_id: str
    after_id: str
    added_findings: tuple[FindingChange, ...] = ()
    removed_findings: tuple[FindingChange, ...] = ()
    changed_findings: tuple[FindingChange, ...] = ()
    posture_before: int | None = None
    posture_after: int | None = None
    confidence_before: int | None = None
    confidence_after: int | None = None
    evidence_added: tuple[str, ...] = ()
    evidence_removed: tuple[str, ...] = ()
    provider_changes: tuple[str, ...] = ()
    conflict_before: bool | None = None
    conflict_after: bool | None = None
    detection_changes: tuple[str, ...] = ()
    limited: bool = False
    limitation: str | None = None


def compare(
    before: WorkspaceInvestigation, after: WorkspaceInvestigation
) -> InvestigationComparison:
    """Compare only stable reasoning fields; no new severity is inferred."""
    before_value = (
        before.investigation_summary.entity_value if before.investigation_summary else None
    )
    after_value = after.investigation_summary.entity_value if after.investigation_summary else None
    if before_value and after_value and before_value != after_value:
        raise ValueError("Investigations must describe the same normalized entity")
    old = {
        f.id: f
        for f in (before.investigation_summary.findings if before.investigation_summary else ())
    }
    new = {
        f.id: f
        for f in (after.investigation_summary.findings if after.investigation_summary else ())
    }
    added = tuple(
        FindingChange(
            finding_id=f.id, title=f.title, severity_after=int(f.severity), change="added"
        )
        for fid, f in sorted(new.items())
        if fid not in old
    )
    removed = tuple(
        FindingChange(
            finding_id=f.id, title=f.title, severity_before=int(f.severity), change="removed"
        )
        for fid, f in sorted(old.items())
        if fid not in new
    )
    changed = tuple(
        FindingChange(
            finding_id=fid,
            title=new[fid].title,
            severity_before=int(old[fid].severity),
            severity_after=int(new[fid].severity),
            change="severity_changed",
        )
        for fid in sorted(old.keys() & new.keys())
        if old[fid].severity != new[fid].severity
    )
    before_snapshot = before.investigation_snapshot
    after_snapshot = after.investigation_snapshot
    old_evidence = _evidence_keys(before_snapshot)
    new_evidence = _evidence_keys(after_snapshot)
    old_providers = _provider_states(before_snapshot)
    new_providers = _provider_states(after_snapshot)
    limited = before_snapshot is None or after_snapshot is None
    return InvestigationComparison(
        before_id=str(before.id),
        after_id=str(after.id),
        added_findings=added,
        removed_findings=removed,
        changed_findings=changed,
        posture_before=int(before.investigation_summary.posture)
        if before.investigation_summary
        else None,
        posture_after=int(after.investigation_summary.posture)
        if after.investigation_summary
        else None,
        confidence_before=before.investigation_summary.overall_confidence.score
        if before.investigation_summary
        else None,
        confidence_after=after.investigation_summary.overall_confidence.score
        if after.investigation_summary
        else None,
        evidence_added=tuple(sorted(new_evidence - old_evidence)),
        evidence_removed=tuple(sorted(old_evidence - new_evidence)),
        provider_changes=tuple(
            f"{name}: {old_providers.get(name, 'absent')} → {new_providers.get(name, 'absent')}"
            for name in sorted(old_providers.keys() | new_providers.keys())
            if old_providers.get(name) != new_providers.get(name)
        ),
        conflict_before=_conflict(before_snapshot),
        conflict_after=_conflict(after_snapshot),
        detection_changes=_detection_changes(before, after),
        limited=limited,
        limitation="Full provider/evidence comparison unavailable for older summary-only records."
        if limited
        else None,
    )


def _evidence_keys(snapshot: object | None) -> set[str]:
    if snapshot is None:
        return set()
    return {
        f"{item.evidence.type}:{item.evidence.summary}:{item.evidence.value or ''}"
        for item in snapshot.threat_intelligence.evidence  # type: ignore[attr-defined]
    }


def _provider_states(snapshot: object | None) -> dict[str, str]:
    if snapshot is None:
        return {}
    return {
        item.provider: item.status.value
        for item in snapshot.threat_intelligence.providers  # type: ignore[attr-defined]
    }


def _conflict(snapshot: object | None) -> bool | None:
    if snapshot is None:
        return None
    return snapshot.threat_intelligence.agreement.conflicted  # type: ignore[attr-defined,no-any-return]


def _detection_changes(
    before: WorkspaceInvestigation, after: WorkspaceInvestigation
) -> tuple[str, ...]:
    old = (
        {artifact.id: artifact for artifact in before.detection_package.artifacts}
        if before.detection_package
        else {}
    )
    new = (
        {artifact.id: artifact for artifact in after.detection_package.artifacts}
        if after.detection_package
        else {}
    )
    return tuple(
        [f"added:{item}" for item in sorted(new.keys() - old.keys())]
        + [f"removed:{item}" for item in sorted(old.keys() - new.keys())]
    )
