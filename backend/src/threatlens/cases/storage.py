"""Storage abstraction for Case Management (Phase 9.0).

Mirrors :mod:`threatlens.workspace.storage` exactly — the brief is explicit:
"Reuse existing storage approach. Do NOT redesign storage." Cases persist
independently of Workspace: a separate root directory, a separate
:class:`CaseStorage` interface, and a separate :class:`LocalFileStorage`
implementation, so neither subsystem's storage can ever collide with or
depend on the other's.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from .exceptions import CaseNotFoundError, CaseStorageError
from .models import Case


class CaseStorage(ABC):
    """Persistence contract for cases."""

    @abstractmethod
    def save(self, case: Case) -> None:
        """Create or overwrite the record at ``case.id``."""

    @abstractmethod
    def load(self, case_id: UUID) -> Case:
        """Return the record for ``case_id``.

        Raises :class:`~threatlens.cases.exceptions.CaseNotFoundError` if no
        record exists with that id.
        """

    @abstractmethod
    def delete(self, case_id: UUID) -> None:
        """Remove the record for ``case_id``.

        Raises :class:`~threatlens.cases.exceptions.CaseNotFoundError` if no
        record exists with that id.
        """

    @abstractmethod
    def list_all(self) -> list[Case]:
        """Return every saved record, in no particular order."""

    @abstractmethod
    def exists(self, case_id: UUID) -> bool:
        """Whether a record exists for ``case_id``."""


class LocalFileStorage(CaseStorage):
    """One JSON file per case under ``root`` — ``{id}.json``.

    Writes are atomic (write to a temp file, then rename) so a crash mid-write
    never leaves a half-written record. ``list_all`` skips any file that fails
    to parse rather than failing the whole listing — a single corrupt record
    should not make every other case unreachable; ``load`` (a request for one
    specific id) still raises on that same corruption.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CaseStorageError(f"Could not create case storage directory: {root}") from exc

    def _path(self, case_id: UUID) -> Path:
        return self._root / f"{case_id}.json"

    def save(self, case: Case) -> None:
        path = self._path(case.id)
        tmp = path.with_name(f"{path.name}.tmp")
        try:
            tmp.write_text(case.model_dump_json(indent=2))
            tmp.replace(path)
        except OSError as exc:
            raise CaseStorageError(f"Could not save case {case.id}") from exc

    def load(self, case_id: UUID) -> Case:
        path = self._path(case_id)
        if not path.exists():
            raise CaseNotFoundError(case_id)
        try:
            return Case.model_validate_json(path.read_text())
        except (OSError, ValidationError) as exc:
            raise CaseStorageError(f"Corrupt case record: {case_id}") from exc

    def delete(self, case_id: UUID) -> None:
        path = self._path(case_id)
        if not path.exists():
            raise CaseNotFoundError(case_id)
        try:
            path.unlink()
        except OSError as exc:
            raise CaseStorageError(f"Could not delete case {case_id}") from exc

    def list_all(self) -> list[Case]:
        records: list[Case] = []
        for path in sorted(self._root.glob("*.json")):
            try:
                records.append(Case.model_validate_json(path.read_text()))
            except (OSError, ValidationError):
                continue
        return records

    def exists(self, case_id: UUID) -> bool:
        return self._path(case_id).exists()
