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


def compare(
    before: WorkspaceInvestigation, after: WorkspaceInvestigation
) -> InvestigationComparison:
    """Compare only stable reasoning fields; no new severity is inferred."""
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
    )
