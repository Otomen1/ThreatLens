"""Investigation Workspace Framework (Phase 8.0).

A workflow and persistence layer over the existing analytical pipeline — not a
new intelligence engine. The workspace stores, retrieves, filters, and updates
completed investigation results (:class:`~threatlens.reasoning.models.InvestigationSummary`,
:class:`~threatlens.detection.models.DetectionPackage`,
:class:`~threatlens.correlation.models.CorrelationSummary`); it never
generates them, never recomputes them, and never touches the Reasoning,
Detection, Correlation, Exposure, or Identity engines. No AI. No network.

Phase 8.0 ships the full framework — models, a storage abstraction with one
local-file-backed implementation, the service, and the API — with no
authentication (single-user, self-hosted).
"""

from __future__ import annotations

from .config import WorkspaceSettings
from .exceptions import (
    InvestigationNotFoundError,
    WorkspaceError,
    WorkspaceStorageError,
)
from .models import (
    WORKSPACE_FRAMEWORK_VERSION,
    SaveInvestigationRequest,
    UpdateInvestigationRequest,
    WorkspaceInvestigation,
    WorkspaceStatus,
)
from .service import WorkspaceService
from .storage import LocalFileStorage, WorkspaceStorage

__all__ = [
    "WORKSPACE_FRAMEWORK_VERSION",
    "InvestigationNotFoundError",
    "LocalFileStorage",
    "SaveInvestigationRequest",
    "UpdateInvestigationRequest",
    "WorkspaceError",
    "WorkspaceInvestigation",
    "WorkspaceService",
    "WorkspaceSettings",
    "WorkspaceStatus",
    "WorkspaceStorage",
    "WorkspaceStorageError",
]
