"""Investigation Workspace routes: save, load, update, delete, and list completed investigations.

A workflow and persistence layer over the existing analytical pipeline — not a
new intelligence engine. Every endpoint here is thin transport over
:class:`~threatlens.workspace.service.WorkspaceService`; the workspace never
computes an investigation result, it only stores and retrieves whatever the
caller already produced via ``/investigate``, ``/detections``, or (in a future
phase) correlation. No authentication — single-user, self-hosted.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ...entities.types import EntityType
from ...graph import EvidenceGraph, GraphService
from ...reasoning import Severity
from ...timeline import Timeline, TimelineService
from ...workspace import (
    InvestigationNotFoundError,
    LocalFileStorage,
    SaveInvestigationRequest,
    UpdateInvestigationRequest,
    WorkspaceInvestigation,
    WorkspaceService,
    WorkspaceSettings,
    WorkspaceStatus,
)
from ..schemas import WorkspaceListItem, WorkspaceListResponse

router = APIRouter()

# Process-wide workspace service, backed by local-file storage. Built once; the
# storage root is created on first use (see LocalFileStorage.__init__).
_workspace_settings = WorkspaceSettings.from_env()
_workspace_service = WorkspaceService(LocalFileStorage(_workspace_settings.storage_dir))

# The Timeline Framework (Phase 8.1) is stateless — a pure function of
# whatever WorkspaceInvestigation it's given — so one shared instance is
# just a namespace, not a cache; still built once for consistency with every
# other *_service singleton in this module.
_timeline_service = TimelineService()

# The Evidence Relationship Graph Framework (Phase 8.2) is likewise a
# stateless pure function of one WorkspaceInvestigation — a sibling of the
# Timeline service, not a consumer of it.
_graph_service = GraphService()


def get_workspace_service() -> WorkspaceService:
    """Provide the Workspace service (overridable in tests)."""
    return _workspace_service


def get_timeline_service() -> TimelineService:
    """Provide the Timeline service (overridable in tests)."""
    return _timeline_service


def get_graph_service() -> GraphService:
    """Provide the Graph service (overridable in tests)."""
    return _graph_service


def _to_list_item(record: WorkspaceInvestigation) -> WorkspaceListItem:
    return WorkspaceListItem(
        id=record.id,
        title=record.title,
        created_at=record.created_at,
        updated_at=record.updated_at,
        status=record.status,
        tags=record.tags,
        summary=record.summary,
        severity=record.severity,
        investigation_type=record.investigation_type,
    )


@router.post(
    "/api/v1/workspace",
    response_model=WorkspaceInvestigation,
    status_code=201,
)
def save_investigation(
    request: SaveInvestigationRequest,
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
) -> WorkspaceInvestigation:
    """Save a completed investigation. ``investigation_summary``/``detection_package``/
    ``correlation_summary`` are attached verbatim — nothing is recomputed."""
    return service.save(request)


@router.get("/api/v1/workspace", response_model=WorkspaceListResponse)
def list_investigations(
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
    status: Annotated[WorkspaceStatus | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    investigation_type: Annotated[EntityType | None, Query()] = None,
    tag: Annotated[str | None, Query()] = None,
    q: Annotated[
        str | None, Query(description="Case-insensitive search over title/summary/tags")
    ] = None,
) -> WorkspaceListResponse:
    """List saved investigations (metadata only), most recently updated first.

    All filters are optional and combine with AND. Every match is a pure,
    in-memory filter over already-persisted metadata.
    """
    records = service.list(
        status=status,
        severity=severity,
        investigation_type=investigation_type,
        tag=tag,
        query=q,
    )
    items = [_to_list_item(r) for r in records]
    return WorkspaceListResponse(investigations=items, total=len(items))


@router.get("/api/v1/workspace/{investigation_id}", response_model=WorkspaceInvestigation)
def get_investigation(
    investigation_id: UUID,
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
) -> WorkspaceInvestigation:
    """Load one saved investigation, including every attached engine output."""
    try:
        return service.get(investigation_id)
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/workspace/{investigation_id}/timeline", response_model=Timeline)
def get_investigation_timeline(
    investigation_id: UUID,
    workspace: Annotated[WorkspaceService, Depends(get_workspace_service)],
    timeline: Annotated[TimelineService, Depends(get_timeline_service)],
) -> Timeline:
    """Derive the read-only timeline for one saved investigation.

    Consumes the saved record's existing ``investigation_summary`` verbatim;
    never mutates it and never persists timeline data of its own — a
    repeated call against an unchanged saved record always returns a
    byte-identical ``Timeline``. ``404`` if the investigation doesn't exist.
    """
    try:
        record = workspace.get(investigation_id)
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return timeline.build(record)


@router.get("/api/v1/workspace/{investigation_id}/graph", response_model=EvidenceGraph)
def get_investigation_graph(
    investigation_id: UUID,
    workspace: Annotated[WorkspaceService, Depends(get_workspace_service)],
    graph: Annotated[GraphService, Depends(get_graph_service)],
) -> EvidenceGraph:
    """Derive the read-only evidence graph for one saved investigation.

    Consumes the saved record's existing ``investigation_summary`` and
    ``correlation_summary`` verbatim; never mutates either and never
    persists graph data of its own — a repeated call against an unchanged
    saved record always returns a byte-identical ``EvidenceGraph``. ``404``
    if the investigation doesn't exist.
    """
    try:
        record = workspace.get(investigation_id)
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return graph.build(record)


@router.put("/api/v1/workspace/{investigation_id}", response_model=WorkspaceInvestigation)
def update_investigation(
    investigation_id: UUID,
    request: UpdateInvestigationRequest,
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
) -> WorkspaceInvestigation:
    """Partially update a saved investigation's metadata (and/or re-attach an output).

    Only fields present in the request body change; an omitted field keeps its
    current value (see :class:`~threatlens.workspace.models.UpdateInvestigationRequest`).
    """
    try:
        return service.update(investigation_id, request)
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/api/v1/workspace/{investigation_id}", status_code=204)
def delete_investigation(
    investigation_id: UUID,
    service: Annotated[WorkspaceService, Depends(get_workspace_service)],
) -> None:
    """Delete a saved investigation."""
    try:
        service.delete(investigation_id)
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
