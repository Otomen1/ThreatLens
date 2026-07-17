"""Exceptions for the Intelligence Collections Framework (Phase 9.1)."""

from __future__ import annotations

from uuid import UUID


class CollectionError(Exception):
    """Base exception for the Intelligence Collections Framework."""


class CollectionNotFoundError(CollectionError):
    """No collection exists with the given id."""

    def __init__(self, collection_id: UUID) -> None:
        self.collection_id = collection_id
        super().__init__(f"No collection found with id {collection_id}")


class CollectionStorageError(CollectionError):
    """The storage backend could not read or write a record."""
