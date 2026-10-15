"""Saved-investigation storage contract and local JSON implementation.

SQLite and PostgreSQL adapters implement the same interface. Local files use
reentrant cross-process locks and unique atomic writes; serverless production
must select durable PostgreSQL storage instead of ephemeral local files.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from ..atomic_file import atomic_write
from ..storage_lock import file_lock
from .exceptions import InvestigationNotFoundError, WorkspaceStorageError
from .models import WorkspaceInvestigation


class WorkspaceStorage(ABC):
    """Persistence contract for saved investigations."""

    @abstractmethod
    def save(self, record: WorkspaceInvestigation) -> None:
        """Create or overwrite the record at ``record.id``."""

    @abstractmethod
    def load(self, investigation_id: UUID) -> WorkspaceInvestigation:
        """Return the record for ``investigation_id``.

        Raises :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if no record exists with that id.
        """

    @abstractmethod
    def delete(self, investigation_id: UUID) -> None:
        """Remove the record for ``investigation_id``.

        Raises :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if no record exists with that id.
        """

    @abstractmethod
    def list_all(self) -> list[WorkspaceInvestigation]:
        """Return every saved record, in no particular order."""

    @abstractmethod
    def exists(self, investigation_id: UUID) -> bool:
        """Whether a record exists for ``investigation_id``."""

    @abstractmethod
    def lock(self) -> AbstractContextManager[None]:
        """Acquire the storage-wide transaction lock."""


class LocalFileStorage(WorkspaceStorage):
    """One JSON file per investigation under ``root`` â€” ``{id}.json``.

    Writes are atomic (write to a temp file, then rename) so a crash mid-write
    never leaves a half-written record. ``list_all`` skips any file that fails
    to parse rather than failing the whole listing â€” a single corrupt record
    should not make every other saved investigation unreachable; ``load``
    (a request for one specific id) still raises on that same corruption.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceStorageError(
                f"Could not create workspace storage directory: {root}"
            ) from exc

    def _path(self, investigation_id: UUID) -> Path:
        return self._root / f"{investigation_id}.json"

    def save(self, record: WorkspaceInvestigation) -> None:
        path = self._path(record.id)
        try:
            with self.lock():
                atomic_write(path, record.model_dump_json(indent=2))
        except OSError as exc:
            raise WorkspaceStorageError(f"Could not save investigation {record.id}") from exc

    def load(self, investigation_id: UUID) -> WorkspaceInvestigation:
        path = self._path(investigation_id)
        if not path.exists():
            raise InvestigationNotFoundError(investigation_id)
        try:
            return WorkspaceInvestigation.model_validate_json(path.read_text())
        except (OSError, ValidationError) as exc:
            raise WorkspaceStorageError(
                f"Corrupt investigation record: {investigation_id}"
            ) from exc

    def delete(self, investigation_id: UUID) -> None:
        path = self._path(investigation_id)
        if not path.exists():
            raise InvestigationNotFoundError(investigation_id)
        try:
            with self.lock():
                path.unlink()
        except OSError as exc:
            raise WorkspaceStorageError(
                f"Could not delete investigation {investigation_id}"
            ) from exc

    def list_all(self) -> list[WorkspaceInvestigation]:
        records: list[WorkspaceInvestigation] = []
        for path in sorted(self._root.glob("*.json")):
            try:
                records.append(WorkspaceInvestigation.model_validate_json(path.read_text()))
            except (OSError, ValidationError):
                continue
        return records

    def exists(self, investigation_id: UUID) -> bool:
        return self._path(investigation_id).exists()

    def lock(self) -> AbstractContextManager[None]:
        return file_lock(self._root / ".transaction.lock")
