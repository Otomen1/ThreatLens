"""The Case Management service (Phase 9.0).

Pure plumbing over a :class:`~threatlens.cases.storage.CaseStorage` backend,
plus one piece of genuine business logic this subsystem owns: validating
status transitions. Everything else — linking/unlinking a Workspace
investigation, appending a note, filtering — is CRUD over caller-supplied
data, exactly like :class:`~threatlens.workspace.service.WorkspaceService`.

This service depends on :class:`~threatlens.workspace.service.WorkspaceService`
for exactly one thing: confirming a Workspace investigation exists before a
case links to it. It never reads, mutates, or recomputes anything about the
investigation itself — only ``WorkspaceService.get()``, the same read every
other Workspace-adjacent consumer (Timeline, Graph, Report) already uses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from ..workspace.service import WorkspaceService
from .exceptions import InvalidStatusTransitionError
from .models import Case, CaseNote, CasePriority, CaseStatus
from .schemas import AddNoteRequest, CreateCaseRequest, UpdateCaseRequest
from .storage import CaseStorage

# The allowed status-transition graph. OPEN and IN_PROGRESS can move to each
# other and forward; RESOLVED can be reopened to IN_PROGRESS or closed;
# CLOSED has exactly one way out — reopen to OPEN — forcing an explicit
# re-triage rather than jumping straight back into IN_PROGRESS/RESOLVED.
# A status "changing" to its own current value is not a transition at all
# (see ``_validate_transition`` below) and is always a no-op, never checked
# against this graph.
_ALLOWED_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({CaseStatus.IN_PROGRESS, CaseStatus.CLOSED}),
    CaseStatus.IN_PROGRESS: frozenset({CaseStatus.OPEN, CaseStatus.RESOLVED, CaseStatus.CLOSED}),
    CaseStatus.RESOLVED: frozenset({CaseStatus.IN_PROGRESS, CaseStatus.CLOSED}),
    CaseStatus.CLOSED: frozenset({CaseStatus.OPEN}),
}


def _validate_transition(current: CaseStatus, requested: CaseStatus) -> None:
    if requested == current:
        return
    if requested not in _ALLOWED_TRANSITIONS[current]:
        raise InvalidStatusTransitionError(current, requested)


class CaseService:
    """Orchestrates persistence, retrieval, filtering, linking, and notes."""

    def __init__(self, storage: CaseStorage, workspace_service: WorkspaceService) -> None:
        self._storage = storage
        self._workspace = workspace_service

    def create(self, request: CreateCaseRequest, *, now: datetime | None = None) -> Case:
        """Persist a new case; returns it with a fresh id.

        ``id`` is always a fresh ``uuid4()`` — creating two cases with
        identical content produces two distinct records, never a collision.
        """
        timestamp = now or datetime.now(UTC)
        case = Case(
            id=uuid4(),
            title=request.title,
            description=request.description,
            status=request.status,
            priority=request.priority,
            created_at=timestamp,
            updated_at=timestamp,
            owner=request.owner,
            tags=request.tags,
            metadata=request.metadata,
        )
        self._storage.save(case)
        return case

    def get(self, case_id: UUID) -> Case:
        """Return one case.

        Raises :class:`~threatlens.cases.exceptions.CaseNotFoundError` if no
        record exists with that id.
        """
        return self._storage.load(case_id)

    def update(
        self, case_id: UUID, request: UpdateCaseRequest, *, now: datetime | None = None
    ) -> Case:
        """Apply a partial update; only fields explicitly set on ``request`` change.

        If ``request.status`` is present and differs from the case's current
        status, the transition is validated first — an invalid transition
        raises :class:`~threatlens.cases.exceptions.InvalidStatusTransitionError`
        and leaves the stored case entirely unchanged.

        Raises :class:`~threatlens.cases.exceptions.CaseNotFoundError` if no
        record exists with that id.
        """
        existing = self._storage.load(case_id)
        changes = request.model_dump(exclude_unset=True)
        if "status" in changes:
            _validate_transition(existing.status, CaseStatus(changes["status"]))
        # `tags`/`metadata` are non-optional collections on `Case` itself
        # (unlike `description`/`owner`, which are genuinely `X | None`);
        # `model_copy` does not re-validate, so an explicit `null` for either
        # must be normalized to its empty form here rather than ever writing
        # a bare `None` into a field typed as `list`/`dict`.
        if changes.get("tags") is None and "tags" in changes:
            changes["tags"] = []
        if changes.get("metadata") is None and "metadata" in changes:
            changes["metadata"] = {}
        changes["updated_at"] = now or datetime.now(UTC)
        updated = existing.model_copy(update=changes)
        self._storage.save(updated)
        return updated

    def delete(self, case_id: UUID) -> None:
        """Remove a case.

        Raises :class:`~threatlens.cases.exceptions.CaseNotFoundError` if no
        record exists with that id.
        """
        self._storage.delete(case_id)

    def list(
        self,
        *,
        status: CaseStatus | None = None,
        priority: CasePriority | None = None,
        tag: str | None = None,
        owner: str | None = None,
        title: str | None = None,
    ) -> list[Case]:
        """Every case matching all given filters, most recently updated first.

        Filtering is a pure in-memory operation over already-persisted
        records — never a database query, never full-text indexing. ``title``
        is a case-insensitive substring match, mirroring
        :class:`~threatlens.workspace.service.WorkspaceService`'s own search.
        """
        records = self._storage.list_all()
        if status is not None:
            records = [c for c in records if c.status == status]
        if priority is not None:
            records = [c for c in records if c.priority == priority]
        if tag is not None:
            records = [c for c in records if tag in c.tags]
        if owner is not None:
            records = [c for c in records if c.owner == owner]
        if title:
            needle = title.lower()
            records = [c for c in records if needle in c.title.lower()]
        return sorted(records, key=lambda c: c.updated_at, reverse=True)

    def link_workspace(
        self, case_id: UUID, workspace_id: UUID, *, now: datetime | None = None
    ) -> Case:
        """Link one Workspace investigation to a case.

        Confirms the investigation exists via
        ``WorkspaceService.get()`` (raising
        :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if not — the route layer maps this to the same 404 every other
        Workspace-adjacent endpoint already uses) before linking, so a case
        can never reference a nonexistent investigation. Idempotent: linking
        an already-linked id is a no-op and leaves ``updated_at`` unchanged.
        """
        self._workspace.get(workspace_id)
        existing = self._storage.load(case_id)
        if workspace_id in existing.linked_workspace_ids:
            return existing
        updated = existing.model_copy(
            update={
                "linked_workspace_ids": [*existing.linked_workspace_ids, workspace_id],
                "updated_at": now or datetime.now(UTC),
            }
        )
        self._storage.save(updated)
        return updated

    def unlink_workspace(
        self, case_id: UUID, workspace_id: UUID, *, now: datetime | None = None
    ) -> Case:
        """Unlink one Workspace investigation from a case.

        Idempotent: unlinking an id that isn't currently linked is a no-op
        and leaves ``updated_at`` unchanged. Never touches the referenced
        investigation itself.
        """
        existing = self._storage.load(case_id)
        if workspace_id not in existing.linked_workspace_ids:
            return existing
        updated = existing.model_copy(
            update={
                "linked_workspace_ids": [
                    wid for wid in existing.linked_workspace_ids if wid != workspace_id
                ],
                "updated_at": now or datetime.now(UTC),
            }
        )
        self._storage.save(updated)
        return updated

    def add_note(
        self, case_id: UUID, request: AddNoteRequest, *, now: datetime | None = None
    ) -> Case:
        """Append one analyst note to a case. Notes are never edited or removed."""
        existing = self._storage.load(case_id)
        note = CaseNote(
            author=request.author,
            timestamp=now or datetime.now(UTC),
            content=request.content,
        )
        updated = existing.model_copy(
            update={
                "notes": [*existing.notes, note],
                "updated_at": now or datetime.now(UTC),
            }
        )
        self._storage.save(updated)
        return updated
