"""Data models for Case Management (Phase 9.0).

A Case is an operational object that organizes one or more Workspace
investigations; it is not a new analytical artifact and never duplicates one.
The relationship is one-directional and read-only in one sense only: a case
references a :class:`~threatlens.workspace.models.WorkspaceInvestigation` by
id, never by copying its content, and linking/unlinking a case never mutates
the referenced investigation. Workspace itself has no notion of cases —
dependency flows one way, from ``cases`` down into ``workspace``, never back.

Unlike the frozen, pure-projection models the Workspace platform produces
(``Timeline``, ``EvidenceGraph``, ``InvestigationReport``), :class:`Case` is
explicitly mutable — mirroring
:class:`~threatlens.workspace.models.WorkspaceInvestigation` itself: a case is
an operational record edited over its lifetime (status, priority, tags,
linked investigations, notes), not a deterministic derivation of something
else.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

CASE_FRAMEWORK_VERSION = "1.0"

MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_NOTE_LENGTH = 4000
MAX_AUTHOR_LENGTH = 200


class CaseStatus(StrEnum):
    """Lifecycle state of a case. Analyst-controlled, never inferred.

    Transitions are validated by :mod:`threatlens.cases.service` against a
    fixed graph (documented there) — not every status is reachable from
    every other status in one step.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(StrEnum):
    """Analyst-assigned priority. No default derivation from case content —
    unlike :class:`~threatlens.reasoning.models.Severity`, which the Reasoning
    Engine computes from evidence, priority here is a pure operational
    judgment call with no analytical basis to compute it from."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseNote(BaseModel):
    """One append-only analyst note.

    Frozen and immutable by design — the brief is explicit: "No editing. No
    deletion." A note is never updated or removed once added; the only way a
    case's note history changes is by appending a new one. No markdown or
    other rendering is implied by ``content``; it is stored and returned
    verbatim as plain text.
    """

    model_config = ConfigDict(frozen=True)

    author: str = Field(min_length=1, max_length=MAX_AUTHOR_LENGTH)
    timestamp: datetime
    content: str = Field(min_length=1, max_length=MAX_NOTE_LENGTH)


class Case(BaseModel):
    """An operational case organizing zero or more Workspace investigations.

    ``id`` is a randomly generated identifier (``uuid4``), matching
    :class:`~threatlens.workspace.models.WorkspaceInvestigation`'s own
    identity convention — a case is a mutable, analyst-owned record, not a
    deterministic recomputation of anything, so two cases with identical
    content are two distinct records, not a collision.

    ``linked_workspace_ids`` holds only ids — never a copy of the referenced
    investigation's content. The relationship is many-to-many: a single
    investigation may be linked from multiple cases, and nothing here
    enforces or assumes a one-to-one relationship. Order is insertion order
    with no duplicates (see :mod:`threatlens.cases.service`).

    ``notes`` is append-only, in the order notes were added (oldest first).

    ``metadata`` is a deliberately open, unopinionated extension point — a
    free-form JSON-compatible bag for future case attributes that don't yet
    warrant a first-class field. No current code path reads it.
    """

    id: UUID
    title: str = Field(min_length=1, max_length=MAX_TITLE_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    status: CaseStatus = CaseStatus.OPEN
    priority: CasePriority = CasePriority.MEDIUM
    created_at: datetime
    updated_at: datetime
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    linked_workspace_ids: list[UUID] = Field(default_factory=list)
    notes: list[CaseNote] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
