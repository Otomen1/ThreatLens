"""Case Management routes: create, load, update, delete, list, link/unlink
Workspace investigations, and append notes.

An operational layer over the Workspace platform — not a new analytical
subsystem. Every endpoint here is thin transport over
:class:`~threatlens.cases.service.CaseService`; the service never recomputes
or duplicates a linked investigation's content, it only stores a reference to
its id. No authentication — single-user, self-hosted, matching every other
Workspace-adjacent route.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ...cases import (
    AddNoteRequest,
    Case,
    CaseListResponse,
    CaseNotFoundError,
    CasePriority,
    CaseService,
    CaseSettings,
    CaseStatus,
    CreateCaseRequest,
    InvalidStatusTransitionError,
    LinkWorkspaceRequest,
    LocalFileStorage,
    UpdateCaseRequest,
)
from ...workspace.exceptions import InvestigationNotFoundError
from .workspace import get_workspace_service

router = APIRouter()

# Process-wide case service, backed by local-file storage, built lazily on
# first use — mirrors ``routes/workspace.py``'s own ``get_workspace_service``
# exactly, for the same reason: constructing ``LocalFileStorage`` at module
# scope means a read-only or misconfigured default directory (e.g. a
# serverless deployment whose only writable path is /tmp) fails the entire
# module import, taking down every route in the app, not just the case ones.
# Only success is memoized: a failed attempt leaves this ``None`` so the next
# call retries rather than staying permanently broken for the life of the
# process.
_case_service: CaseService | None = None


def get_case_service() -> CaseService:
    """Provide the Case service (overridable in tests).

    Builds the singleton on first call, composing the already-lazily-built
    Workspace service singleton — mirrors
    :func:`~threatlens.api.routes.workspace.get_report_service`'s
    composition of its own sibling singletons. Raises
    :class:`~threatlens.cases.exceptions.CaseStorageError` if the configured
    storage directory cannot be created — a failure scoped to whichever case
    request triggered it, never to app import or to any unrelated route.
    """
    global _case_service
    if _case_service is None:
        settings = CaseSettings.from_env()
        _case_service = CaseService(LocalFileStorage(settings.storage_dir), get_workspace_service())
    return _case_service


@router.post("/api/v1/cases", response_model=Case, status_code=201)
def create_case(
    request: CreateCaseRequest,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> Case:
    """Create a new case."""
    return service.create(request)


@router.get("/api/v1/cases", response_model=CaseListResponse)
def list_cases(
    service: Annotated[CaseService, Depends(get_case_service)],
    status: Annotated[CaseStatus | None, Query()] = None,
    priority: Annotated[CasePriority | None, Query()] = None,
    tag: Annotated[str | None, Query()] = None,
    owner: Annotated[str | None, Query()] = None,
    title: Annotated[
        str | None, Query(description="Case-insensitive substring match on title")
    ] = None,
) -> CaseListResponse:
    """List cases (full records), most recently updated first.

    All filters are optional and combine with AND. Every match is a pure,
    in-memory filter over already-persisted records — no full-text indexing.
    """
    cases = service.list(status=status, priority=priority, tag=tag, owner=owner, title=title)
    return CaseListResponse(cases=cases, total=len(cases))


@router.get("/api/v1/cases/{case_id}", response_model=Case)
def get_case(
    case_id: UUID,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> Case:
    """Load one case."""
    try:
        return service.get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/api/v1/cases/{case_id}", response_model=Case)
def update_case(
    case_id: UUID,
    request: UpdateCaseRequest,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> Case:
    """Partially update a case's metadata (and/or transition its status).

    Only fields present in the request body change; an omitted field keeps
    its current value. A status change is validated against the allowed
    transition graph — an invalid transition returns ``409`` and leaves the
    case unchanged.
    """
    try:
        return service.update(case_id, request)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidStatusTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete("/api/v1/cases/{case_id}", status_code=204)
def delete_case(
    case_id: UUID,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> None:
    """Delete a case. Never touches any linked Workspace investigation."""
    try:
        service.delete(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/cases/{case_id}/workspace", response_model=Case)
def link_workspace(
    case_id: UUID,
    request: LinkWorkspaceRequest,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> Case:
    """Link one Workspace investigation to a case.

    ``404`` if either the case or the referenced investigation doesn't
    exist. Idempotent: linking an already-linked investigation is a no-op.
    """
    try:
        return service.link_workspace(case_id, request.workspace_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/api/v1/cases/{case_id}/workspace/{workspace_id}", response_model=Case)
def unlink_workspace(
    case_id: UUID,
    workspace_id: UUID,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> Case:
    """Unlink one Workspace investigation from a case.

    ``404`` if the case doesn't exist. Idempotent: unlinking an id that
    isn't currently linked is a no-op. Never touches the investigation
    itself — returns the updated case, not ``204``, since the case (unlike a
    deleted case) still exists and the caller almost always wants its new
    state without a second fetch.
    """
    try:
        return service.unlink_workspace(case_id, workspace_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/cases/{case_id}/notes", response_model=Case, status_code=201)
def add_note(
    case_id: UUID,
    request: AddNoteRequest,
    service: Annotated[CaseService, Depends(get_case_service)],
) -> Case:
    """Append one analyst note to a case. Notes are never edited or removed."""
    try:
        return service.add_note(case_id, request)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
