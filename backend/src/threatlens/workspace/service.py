"""The Investigation Workspace service (Phase 8.0).

Pure plumbing over a :class:`~threatlens.workspace.storage.WorkspaceStorage`
backend: save, load, update, delete, list, and filter saved investigations.
No investigation logic, no reasoning, no correlation — every field this
service touches is either workspace metadata (title, status, tags, ...) or an
already-computed engine output attached verbatim by the caller.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from ..entities.types import EntityType
from ..reasoning import Severity
from .models import (
    SaveInvestigationRequest,
    UpdateInvestigationRequest,
    WorkspaceInvestigation,
    WorkspaceStatus,
)
from .storage import WorkspaceStorage


class WorkspaceService:
    """Orchestrates persistence, retrieval, filtering, and metadata updates."""

    def __init__(self, storage: WorkspaceStorage) -> None:
        self._storage = storage

    def save(
        self, request: SaveInvestigationRequest, *, now: datetime | None = None
    ) -> WorkspaceInvestigation:
        """Persist a new investigation record; returns it with a fresh id.

        ``id`` is always a fresh ``uuid4()`` — saving the same content twice
        (e.g. re-saving after editing the analyst summary) creates a second,
        distinct record rather than overwriting the first.
        """
        timestamp = now or datetime.now(UTC)
        record = WorkspaceInvestigation(
            id=uuid4(),
            title=request.title,
            created_at=timestamp,
            updated_at=timestamp,
            status=request.status,
            tags=request.tags,
            summary=request.summary,
            severity=request.severity,
            investigation_type=request.investigation_type,
            investigation_summary=request.investigation_summary,
            detection_package=request.detection_package,
            correlation_summary=request.correlation_summary,
        )
        self._storage.save(record)
        return record

    def get(self, investigation_id: UUID) -> WorkspaceInvestigation:
        """Return one saved investigation.

        Raises :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if no record exists with that id.
        """
        return self._storage.load(investigation_id)

    def update(
        self,
        investigation_id: UUID,
        request: UpdateInvestigationRequest,
        *,
        now: datetime | None = None,
    ) -> WorkspaceInvestigation:
        """Apply a partial update; only fields explicitly set on ``request`` change.

        Raises :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if no record exists with that id.
        """
        existing = self._storage.load(investigation_id)
        changes = request.model_dump(exclude_unset=True)
        changes["updated_at"] = now or datetime.now(UTC)
        updated = existing.model_copy(update=changes)
        self._storage.save(updated)
        return updated

    def delete(self, investigation_id: UUID) -> None:
        """Remove a saved investigation.

        Raises :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if no record exists with that id.
        """
        self._storage.delete(investigation_id)

    def list(
        self,
        *,
        status: WorkspaceStatus | None = None,
        severity: Severity | None = None,
        investigation_type: EntityType | None = None,
        tag: str | None = None,
        query: str | None = None,
    ) -> list[WorkspaceInvestigation]:
        """Every saved investigation matching all given filters, most recently updated first.

        Filtering and search are pure in-memory operations over already-persisted
        metadata — never a database query, never reasoning, never correlation.
        """
        records = self._storage.list_all()
        if status is not None:
            records = [r for r in records if r.status == status]
        if severity is not None:
            records = [r for r in records if r.severity == severity]
        if investigation_type is not None:
            records = [r for r in records if r.investigation_type == investigation_type]
        if tag is not None:
            records = [r for r in records if tag in r.tags]
        if query:
            needle = query.lower()
            records = [r for r in records if _matches(r, needle)]
        return sorted(records, key=lambda r: r.updated_at, reverse=True)


def _matches(record: WorkspaceInvestigation, needle: str) -> bool:
    """Case-insensitive substring search over title, summary, and tags."""
    if needle in record.title.lower():
        return True
    if record.summary and needle in record.summary.lower():
        return True
    return any(needle in t.lower() for t in record.tags)
