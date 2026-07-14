"""Exceptions for the Investigation Workspace (Phase 8.0)."""

from __future__ import annotations

from uuid import UUID


class WorkspaceError(Exception):
    """Base exception for the Investigation Workspace."""


class InvestigationNotFoundError(WorkspaceError):
    """No saved investigation exists with the given id."""

    def __init__(self, investigation_id: UUID) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"No investigation found with id {investigation_id}")


class WorkspaceStorageError(WorkspaceError):
    """The storage backend could not read or write a record."""
