"""Data models for the Investigation Workspace (Phase 8.0).

The workspace persists completed investigation results; it never computes
them. ``investigation_summary``, ``detection_package``, and
``correlation_summary`` are the existing, frozen output models of the
Reasoning, Detection, and Correlation engines respectively, imported and
persisted verbatim. This module defines only the workspace's own metadata
envelope around them — nothing here duplicates engine logic or re-declares an
engine's model.

Note on "Investigation Summary" vs. "Reasoning Summary": ThreatLens has exactly
one model for a completed investigation's deterministic reasoning output —
:class:`~threatlens.reasoning.models.InvestigationSummary`, produced by the
Investigation Intelligence Engine's ``reason()``. There is no second,
independent "reasoning summary" model in the codebase. Rather than invent a
duplicate to satisfy two separate labels, this phase reuses the one existing
model for both — consistent with "reuse existing models wherever possible"
and "avoid duplication".

Unlike every other model in this codebase, :class:`WorkspaceInvestigation` is
**not** frozen. It is the one ThreatLens model explicitly designed to be
mutated over its lifetime (status transitions, tag edits, title renames,
re-attaching a later-generated detection package). Every nested engine output
it references remains frozen exactly as that engine produced it; only the
workspace's own envelope changes.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from ..correlation import CorrelationSummary
from ..detection import DetectionPackage
from ..entities.types import EntityType
from ..reasoning import InvestigationSummary, Severity

WORKSPACE_FRAMEWORK_VERSION = "1.0"

MAX_TITLE_LENGTH = 200
MAX_SUMMARY_LENGTH = 2000


class WorkspaceStatus(StrEnum):
    """Lifecycle state of a saved investigation. Analyst-controlled, never inferred."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ARCHIVED = "archived"


class WorkspaceInvestigation(BaseModel):
    """A saved investigation record.

    ``id`` is a randomly generated identifier (``uuid4``), not a content
    hash — matching the existing ``search_id``/``investigation_id`` convention
    used by ``/detect`` and ``/investigate`` (both also ``uuid4()``). This is
    deliberately different from the Detection/Correlation engines'
    content-addressed ids: a saved investigation is a mutable, analyst-owned
    record, not a pure recomputation of deterministic engine output, so two
    saves of identical content are two distinct records, not a collision.

    ``investigation_summary``, ``detection_package``, and
    ``correlation_summary`` are all optional: the workspace does not require
    every downstream engine to have run before a record can be saved, and
    Correlation in particular is not yet wired into ``/investigate`` (Phase
    7.x), so it will typically be absent until a later phase.
    """

    id: UUID
    title: str = Field(min_length=1, max_length=MAX_TITLE_LENGTH)
    created_at: datetime
    updated_at: datetime
    status: WorkspaceStatus = WorkspaceStatus.OPEN
    tags: list[str] = Field(default_factory=list)
    summary: str | None = Field(default=None, max_length=MAX_SUMMARY_LENGTH)
    severity: Severity | None = None
    investigation_type: EntityType
    investigation_summary: InvestigationSummary | None = None
    detection_package: DetectionPackage | None = None
    correlation_summary: CorrelationSummary | None = None


class SaveInvestigationRequest(BaseModel):
    """Input to create a new saved investigation.

    Deliberately excludes ``id``/``created_at``/``updated_at`` — those are
    always assigned by :class:`~threatlens.workspace.service.WorkspaceService`,
    never supplied by the caller.
    """

    title: str = Field(min_length=1, max_length=MAX_TITLE_LENGTH)
    status: WorkspaceStatus = WorkspaceStatus.OPEN
    tags: list[str] = Field(default_factory=list)
    summary: str | None = Field(default=None, max_length=MAX_SUMMARY_LENGTH)
    severity: Severity | None = None
    investigation_type: EntityType
    investigation_summary: InvestigationSummary | None = None
    detection_package: DetectionPackage | None = None
    correlation_summary: CorrelationSummary | None = None


class UpdateInvestigationRequest(BaseModel):
    """Partial update for a saved investigation.

    Every field is optional; only fields explicitly present in the request
    (including an explicit ``null``) are changed — an omitted field leaves the
    existing value untouched. This is standard PATCH-style partial-update
    semantics; ``PUT /api/v1/workspace/{id}`` uses it (rather than requiring a
    full replacement body) so simple actions like "change status" or "add a
    tag" don't require resending the entire record.
    """

    title: str | None = Field(default=None, min_length=1, max_length=MAX_TITLE_LENGTH)
    status: WorkspaceStatus | None = None
    tags: list[str] | None = None
    summary: str | None = Field(default=None, max_length=MAX_SUMMARY_LENGTH)
    severity: Severity | None = None
    investigation_type: EntityType | None = None
    investigation_summary: InvestigationSummary | None = None
    detection_package: DetectionPackage | None = None
    correlation_summary: CorrelationSummary | None = None
