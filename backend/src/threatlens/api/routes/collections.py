"""Intelligence Collections routes: create, load, update, delete, list,
search, add/remove indicators, and link Workspace investigations/Cases.

Reusable, analyst-curated sets of threat intelligence — not a new analytical
subsystem. Every endpoint here is thin transport over
:class:`~threatlens.collections.service.CollectionService`; the service never
computes, enriches, or classifies an indicator, it only stores exactly what
the caller provided, and it never duplicates a linked investigation's or
case's content, only a reference to its id. No authentication — single-user,
self-hosted, matching every other route in this API.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ...cases import CaseNotFoundError
from ...collections import (
    AddIndicatorRequest,
    Collection,
    CollectionListItem,
    CollectionListResponse,
    CollectionNotFoundError,
    CollectionService,
    CollectionSettings,
    CreateCollectionRequest,
    IndicatorType,
    LinkCaseRequest,
    LinkWorkspaceRequest,
    LocalFileStorage,
    RemoveIndicatorRequest,
    UpdateCollectionRequest,
)
from ...workspace.exceptions import InvestigationNotFoundError
from .cases import get_case_service
from .workspace import get_workspace_service

router = APIRouter()

# Process-wide collection service, backed by local-file storage, built lazily
# on first use — mirrors ``routes/cases.py``'s own ``get_case_service``
# exactly, for the same reason: constructing ``LocalFileStorage`` at module
# scope means a read-only or misconfigured default directory (e.g. a
# serverless deployment whose only writable path is /tmp) fails the entire
# module import, taking down every route in the app, not just the collection
# ones. Only success is memoized: a failed attempt leaves this ``None`` so
# the next call retries rather than staying permanently broken for the life
# of the process.
_collection_service: CollectionService | None = None


def get_collection_service() -> CollectionService:
    """Provide the Collection service (overridable in tests).

    Builds the singleton on first call, composing the already-lazily-built
    Workspace and Case service singletons — mirrors
    :func:`~threatlens.api.routes.cases.get_case_service`'s own composition
    of its Workspace sibling. Raises
    :class:`~threatlens.collections.exceptions.CollectionStorageError` if the
    configured storage directory cannot be created — a failure scoped to
    whichever collection request triggered it, never to app import or to any
    unrelated route.
    """
    global _collection_service
    if _collection_service is None:
        settings = CollectionSettings.from_env()
        _collection_service = CollectionService(
            LocalFileStorage(settings.storage_dir),
            get_workspace_service(),
            get_case_service(),
        )
    return _collection_service


def _to_list_item(record: Collection) -> CollectionListItem:
    return CollectionListItem(
        id=record.id,
        name=record.name,
        description=record.description,
        category=record.category,
        tags=record.tags,
        source=record.source,
        created_at=record.created_at,
        updated_at=record.updated_at,
        linked_case_ids=record.linked_case_ids,
        linked_workspace_ids=record.linked_workspace_ids,
        metadata=record.metadata,
        indicator_count=len(record.indicators),
    )


@router.post("/api/v1/collections", response_model=Collection, status_code=201)
def create_collection(
    request: CreateCollectionRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Create a new collection."""
    return service.create(request)


@router.get("/api/v1/collections", response_model=CollectionListResponse)
def list_collections(
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> CollectionListResponse:
    """Browse every collection (metadata only), most recently updated first.

    Unfiltered — see ``GET /api/v1/collections/search`` for deterministic
    filtering. Returns ``indicator_count`` rather than the full ``indicators``
    list: a collection's indicator list can grow large (unlike a case's notes
    or linked-investigation ids), so the full list is available only from
    ``GET /api/v1/collections/{id}``.
    """
    records = service.list()
    return CollectionListResponse(
        collections=[_to_list_item(r) for r in records], total=len(records)
    )


# Registered ahead of ``GET /api/v1/collections/{collection_id}`` below so the
# literal path segment ``search`` is matched by this route first — Starlette
# resolves ambiguous paths in registration order, and a later-registered
# ``{collection_id}`` route would otherwise capture "search" as its path
# parameter and fail UUID coercion with a 422 that never reaches this handler.
@router.get("/api/v1/collections/search", response_model=CollectionListResponse)
def search_collections(
    service: Annotated[CollectionService, Depends(get_collection_service)],
    name: Annotated[
        str | None, Query(description="Case-insensitive substring match on name")
    ] = None,
    category: Annotated[str | None, Query()] = None,
    indicator_type: Annotated[IndicatorType | None, Query()] = None,
    tag: Annotated[str | None, Query()] = None,
    linked_case_id: Annotated[UUID | None, Query()] = None,
    linked_workspace_id: Annotated[UUID | None, Query()] = None,
) -> CollectionListResponse:
    """Deterministically filter collections (metadata only).

    All filters are optional and combine with AND. No fuzzy search, no AI, no
    embeddings — every match is a pure, in-memory filter over already-
    persisted records.
    """
    records = service.list(
        name=name,
        category=category,
        indicator_type=indicator_type,
        tag=tag,
        linked_case_id=linked_case_id,
        linked_workspace_id=linked_workspace_id,
    )
    return CollectionListResponse(
        collections=[_to_list_item(r) for r in records], total=len(records)
    )


@router.get("/api/v1/collections/{collection_id}", response_model=Collection)
def get_collection(
    collection_id: UUID,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Load one collection, including its full indicator list."""
    try:
        return service.get(collection_id)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/api/v1/collections/{collection_id}", response_model=Collection)
def update_collection(
    collection_id: UUID,
    request: UpdateCollectionRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Partially update a collection's own metadata.

    Only fields present in the request body change; an omitted field keeps
    its current value.
    """
    try:
        return service.update(collection_id, request)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/api/v1/collections/{collection_id}", status_code=204)
def delete_collection(
    collection_id: UUID,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> None:
    """Delete a collection. Never touches any linked Workspace investigation or Case."""
    try:
        service.delete(collection_id)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/api/v1/collections/{collection_id}/indicator", response_model=Collection, status_code=201
)
def add_indicator(
    collection_id: UUID,
    request: AddIndicatorRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Add one indicator to a collection.

    Deduplicated by ``(type, normalized_value)``: if an indicator with the
    same identity already exists, the two are merged (widened seen-range,
    unioned tags, newest non-null confidence/source/notes) rather than
    creating a duplicate.
    """
    try:
        return service.add_indicator(collection_id, request)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/api/v1/collections/{collection_id}/indicator", response_model=Collection)
def remove_indicator(
    collection_id: UUID,
    request: RemoveIndicatorRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Remove one indicator from a collection, matched by ``(type, normalized_value)``.

    There is no synthetic indicator id to address in the URL, so the identity
    to remove is given in the request body. Idempotent: removing an identity
    that isn't present is a no-op. Returns the updated collection rather than
    ``204`` since the collection itself still exists.
    """
    try:
        return service.remove_indicator(collection_id, request)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/collections/{collection_id}/workspace", response_model=Collection)
def link_workspace(
    collection_id: UUID,
    request: LinkWorkspaceRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Link one Workspace investigation to a collection.

    ``404`` if either the collection or the referenced investigation doesn't
    exist. Idempotent: linking an already-linked investigation is a no-op.
    """
    try:
        return service.link_workspace(collection_id, request.workspace_id)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvestigationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/collections/{collection_id}/case", response_model=Collection)
def link_case(
    collection_id: UUID,
    request: LinkCaseRequest,
    service: Annotated[CollectionService, Depends(get_collection_service)],
) -> Collection:
    """Link one Case to a collection.

    ``404`` if either the collection or the referenced case doesn't exist.
    Idempotent: linking an already-linked case is a no-op.
    """
    try:
        return service.link_case(collection_id, request.case_id)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
