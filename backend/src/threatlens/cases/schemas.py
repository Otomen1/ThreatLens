"""Request/response DTOs for Case Management (Phase 9.0).

Kept in the ``cases`` package itself, alongside the domain model — the same
placement rationale as
:class:`~threatlens.workspace.models.SaveInvestigationRequest`/
:class:`~threatlens.workspace.models.UpdateInvestigationRequest`: these are
this subsystem's own request/response shapes, not a generic cross-subsystem
API concern, so they live with the domain they belong to rather than in the
shared ``api/schemas.py`` grab-bag.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field, JsonValue

from .models import (
    MAX_AUTHOR_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    MAX_NOTE_LENGTH,
    MAX_TITLE_LENGTH,
    Case,
    CasePriority,
    CaseStatus,
)


class CreateCaseRequest(BaseModel):
    """Input to create a new case.

    Deliberately excludes ``id``/``created_at``/``updated_at``/
    ``linked_workspace_ids``/``notes`` — those are always assigned or
    appended by :class:`~threatlens.cases.service.CaseService`, never
    supplied directly by the caller. Linking an investigation or adding a
    note is a separate action (``POST .../workspace``, ``POST .../notes``),
    not part of case creation.
    """

    title: str = Field(min_length=1, max_length=MAX_TITLE_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    status: CaseStatus = CaseStatus.OPEN
    priority: CasePriority = CasePriority.MEDIUM
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class UpdateCaseRequest(BaseModel):
    """Partial update for a case's own metadata.

    Every field is optional; only fields explicitly present in the request
    (including an explicit ``null``) are changed — an omitted field leaves
    the existing value untouched. Standard PATCH-style partial-update
    semantics, matching
    :class:`~threatlens.workspace.models.UpdateInvestigationRequest`.

    A ``status`` change is validated against the allowed transition graph
    (see :mod:`threatlens.cases.service`) before being applied; an invalid
    transition raises
    :class:`~threatlens.cases.exceptions.InvalidStatusTransitionError` and
    leaves the case entirely unchanged.
    """

    title: str | None = Field(default=None, min_length=1, max_length=MAX_TITLE_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    status: CaseStatus | None = None
    priority: CasePriority | None = None
    owner: str | None = None
    tags: list[str] | None = None
    metadata: dict[str, JsonValue] | None = None


class LinkWorkspaceRequest(BaseModel):
    """Input to link one Workspace investigation to a case."""

    workspace_id: UUID


class AddNoteRequest(BaseModel):
    """Input to append one analyst note to a case."""

    author: str = Field(min_length=1, max_length=MAX_AUTHOR_LENGTH)
    content: str = Field(min_length=1, max_length=MAX_NOTE_LENGTH)


class CaseListResponse(BaseModel):
    """The full result of ``GET /api/v1/cases``: matching cases plus a count.

    Returns full :class:`~threatlens.cases.models.Case` records, not a
    slimmed list-item projection — unlike
    :class:`~threatlens.api.schemas.WorkspaceListResponse`, which omits its
    heavy nested engine-output payloads for exactly this reason. A case has
    no equivalent heavy payload (its largest fields are small lists of ids
    and short notes), so there is nothing worth slimming, and inventing a
    parallel "CaseListItem" model would only duplicate ``Case`` for no
    benefit.
    """

    cases: list[Case]
    total: int
