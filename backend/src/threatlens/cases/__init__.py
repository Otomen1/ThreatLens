"""Case Management (Phase 9.0).

An operational layer above the Workspace platform — not a new analytical
subsystem. A :class:`Case` organizes zero or more
:class:`~threatlens.workspace.models.WorkspaceInvestigation` records by
reference (id only, never a content copy); Workspace itself has no notion of
cases. No AI, no network, no automation. Mirrors
:mod:`threatlens.workspace`'s own architecture exactly: models, a storage
abstraction with one local-file-backed implementation, a thin service, and
an API — with no authentication (single-user, self-hosted), per the phase
brief.
"""

from __future__ import annotations

from .config import CaseSettings
from .exceptions import (
    CaseError,
    CaseNotFoundError,
    CaseStorageError,
    InvalidStatusTransitionError,
)
from .models import (
    CASE_FRAMEWORK_VERSION,
    Case,
    CaseNote,
    CasePriority,
    CaseStatus,
)
from .schemas import (
    AddNoteRequest,
    CaseListResponse,
    CreateCaseRequest,
    LinkWorkspaceRequest,
    UpdateCaseRequest,
)
from .service import CaseService
from .storage import CaseStorage, LocalFileStorage

__all__ = [
    "CASE_FRAMEWORK_VERSION",
    "AddNoteRequest",
    "Case",
    "CaseError",
    "CaseListResponse",
    "CaseNote",
    "CaseNotFoundError",
    "CasePriority",
    "CaseService",
    "CaseSettings",
    "CaseStatus",
    "CaseStorage",
    "CaseStorageError",
    "CreateCaseRequest",
    "InvalidStatusTransitionError",
    "LinkWorkspaceRequest",
    "LocalFileStorage",
    "UpdateCaseRequest",
]
