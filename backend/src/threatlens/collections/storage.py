"""Storage abstraction for the Intelligence Collections Framework (Phase 9.1).

Mirrors :mod:`threatlens.cases.storage` (itself a mirror of
:mod:`threatlens.workspace.storage`) exactly — one local-file-backed
implementation, a separate root directory, and a separate interface, so
collections persist independently of both Workspace and Cases and neither
subsystem's storage can ever collide with or depend on the other's.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from .exceptions import CollectionNotFoundError, CollectionStorageError
from .models import Collection


class CollectionStorage(ABC):
    """Persistence contract for collections."""

    @abstractmethod
    def save(self, collection: Collection) -> None:
        """Create or overwrite the record at ``collection.id``."""

    @abstractmethod
    def load(self, collection_id: UUID) -> Collection:
        """Return the record for ``collection_id``.

        Raises :class:`~threatlens.collections.exceptions.CollectionNotFoundError`
        if no record exists with that id.
        """

    @abstractmethod
    def delete(self, collection_id: UUID) -> None:
        """Remove the record for ``collection_id``.

        Raises :class:`~threatlens.collections.exceptions.CollectionNotFoundError`
        if no record exists with that id.
        """

    @abstractmethod
    def list_all(self) -> list[Collection]:
        """Return every saved record, in no particular order."""

    @abstractmethod
    def exists(self, collection_id: UUID) -> bool:
        """Whether a record exists for ``collection_id``."""


class LocalFileStorage(CollectionStorage):
    """One JSON file per collection under ``root`` — ``{id}.json``.

    Writes are atomic (write to a temp file, then rename) so a crash mid-write
    never leaves a half-written record. ``list_all`` skips any file that fails
    to parse rather than failing the whole listing — a single corrupt record
    should not make every other collection unreachable; ``load`` (a request
    for one specific id) still raises on that same corruption.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CollectionStorageError(
                f"Could not create collection storage directory: {root}"
            ) from exc

    def _path(self, collection_id: UUID) -> Path:
        return self._root / f"{collection_id}.json"

    def save(self, collection: Collection) -> None:
        path = self._path(collection.id)
        tmp = path.with_name(f"{path.name}.tmp")
        try:
            tmp.write_text(collection.model_dump_json(indent=2))
            tmp.replace(path)
        except OSError as exc:
            raise CollectionStorageError(f"Could not save collection {collection.id}") from exc

    def load(self, collection_id: UUID) -> Collection:
        path = self._path(collection_id)
        if not path.exists():
            raise CollectionNotFoundError(collection_id)
        try:
            return Collection.model_validate_json(path.read_text())
        except (OSError, ValidationError) as exc:
            raise CollectionStorageError(f"Corrupt collection record: {collection_id}") from exc

    def delete(self, collection_id: UUID) -> None:
        path = self._path(collection_id)
        if not path.exists():
            raise CollectionNotFoundError(collection_id)
        try:
            path.unlink()
        except OSError as exc:
            raise CollectionStorageError(f"Could not delete collection {collection_id}") from exc

    def list_all(self) -> list[Collection]:
        records: list[Collection] = []
        for path in sorted(self._root.glob("*.json")):
            try:
                records.append(Collection.model_validate_json(path.read_text()))
            except (OSError, ValidationError):
                continue
        return records

    def exists(self, collection_id: UUID) -> bool:
        return self._path(collection_id).exists()
