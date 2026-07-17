"""Request/response DTOs for the Intelligence Collections Framework (Phase 9.1).

Kept in the ``collections`` package itself, alongside the domain model — the
same placement rationale as :mod:`threatlens.cases.schemas`: these are this
subsystem's own request/response shapes, not a generic cross-subsystem API
concern, so they live with the domain they belong to rather than in the
shared ``api/schemas.py`` grab-bag (where ``WorkspaceListItem`` predates that
convention and still lives today).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, JsonValue

from .models import (
    MAX_CATEGORY_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    MAX_NAME_LENGTH,
    MAX_NOTES_LENGTH,
    MAX_SOURCE_LENGTH,
    MAX_VALUE_LENGTH,
    CollectionSource,
    IndicatorType,
)


class CreateCollectionRequest(BaseModel):
    """Input to create a new collection.

    Deliberately excludes ``id``/``created_at``/``updated_at``/
    ``linked_case_ids``/``linked_workspace_ids``/``indicators`` — those are
    always assigned or appended by
    :class:`~threatlens.collections.service.CollectionService`, never
    supplied directly by the caller. Adding an indicator or linking a
    Workspace investigation/Case is a separate action, not part of creation.
    """

    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    category: str | None = Field(default=None, max_length=MAX_CATEGORY_LENGTH)
    tags: list[str] = Field(default_factory=list)
    source: CollectionSource = CollectionSource.MANUAL
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class UpdateCollectionRequest(BaseModel):
    """Partial update for a collection's own metadata.

    Every field is optional; only fields explicitly present in the request
    (including an explicit ``null``) are changed — an omitted field leaves
    the existing value untouched. Standard PATCH-style partial-update
    semantics, matching
    :class:`~threatlens.cases.schemas.UpdateCaseRequest`. ``source`` is not
    updatable here — it is provenance fixed at creation, not editable
    metadata.
    """

    name: str | None = Field(default=None, min_length=1, max_length=MAX_NAME_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    category: str | None = Field(default=None, max_length=MAX_CATEGORY_LENGTH)
    tags: list[str] | None = None
    metadata: dict[str, JsonValue] | None = None


class AddIndicatorRequest(BaseModel):
    """Input to add one indicator to a collection.

    If an indicator with the same ``(type, normalized_value)`` identity
    already exists in the collection, the two are merged (see
    :meth:`~threatlens.collections.service.CollectionService.add_indicator`)
    rather than creating a duplicate.
    """

    type: IndicatorType
    value: str = Field(min_length=1, max_length=MAX_VALUE_LENGTH)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    source: str | None = Field(default=None, max_length=MAX_SOURCE_LENGTH)
    notes: str | None = Field(default=None, max_length=MAX_NOTES_LENGTH)


class RemoveIndicatorRequest(BaseModel):
    """Input to remove one indicator from a collection, matched by identity.

    There is no synthetic indicator id to address in a URL path (an
    :class:`~threatlens.collections.models.Indicator` has none — see its
    docstring); removal is identified the same way addition and
    deduplication are: ``(type, normalized_value)``.
    """

    type: IndicatorType
    value: str = Field(min_length=1, max_length=MAX_VALUE_LENGTH)


class LinkWorkspaceRequest(BaseModel):
    """Input to link one Workspace investigation to a collection."""

    workspace_id: UUID


class LinkCaseRequest(BaseModel):
    """Input to link one Case to a collection."""

    case_id: UUID


class CollectionListItem(BaseModel):
    """One row of ``GET /api/v1/collections`` or ``.../search`` — metadata only.

    Deliberately excludes the full ``indicators`` list in favor of
    ``indicator_count``: unlike a case's notes and linked-investigation id
    list (always small), a collection's indicator list is exactly the kind
    of thing named in the phase brief as growing to hundreds or thousands of
    entries ("Internal Blocklist", "Threat Hunt IOC Pack") — the same "heavy
    nested payload" reasoning that keeps
    :class:`~threatlens.api.schemas.WorkspaceListItem` slim applies here too.
    The full list is available from ``GET /api/v1/collections/{id}``.
    """

    id: UUID
    name: str
    description: str | None
    category: str | None
    tags: list[str]
    source: CollectionSource
    created_at: datetime
    updated_at: datetime
    linked_case_ids: list[UUID]
    linked_workspace_ids: list[UUID]
    metadata: dict[str, JsonValue]
    indicator_count: int


class CollectionListResponse(BaseModel):
    """The full result of ``GET /api/v1/collections`` or ``.../search``."""

    collections: list[CollectionListItem]
    total: int
