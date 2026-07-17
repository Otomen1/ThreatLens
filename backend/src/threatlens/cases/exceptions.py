"""Exceptions for Case Management (Phase 9.0)."""

from __future__ import annotations

from uuid import UUID

from .models import CaseStatus


class CaseError(Exception):
    """Base exception for Case Management."""


class CaseNotFoundError(CaseError):
    """No case exists with the given id."""

    def __init__(self, case_id: UUID) -> None:
        self.case_id = case_id
        super().__init__(f"No case found with id {case_id}")


class CaseStorageError(CaseError):
    """The storage backend could not read or write a record."""


class InvalidStatusTransitionError(CaseError):
    """The requested status change is not allowed from the case's current status."""

    def __init__(self, current: CaseStatus, requested: CaseStatus) -> None:
        self.current = current
        self.requested = requested
        super().__init__(f"Cannot transition a case from '{current}' to '{requested}'")
