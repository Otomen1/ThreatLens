"""Operation-scoped SQLite workspace storage; safe across request threads."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from pathlib import Path
from uuid import UUID

from ..record_database import personal_sqlite_lock, sqlite_connection, sqlite_transaction
from ..sqlite_storage import record_audit
from .exceptions import InvestigationNotFoundError, WorkspaceStorageError
from .models import WorkspaceInvestigation
from .storage import WorkspaceStorage


class SQLiteWorkspaceStorage(WorkspaceStorage):
    def __init__(self, database: Path) -> None:
        self._database = database
        try:
            with sqlite_connection(database):
                pass
        except (OSError, sqlite3.Error) as exc:
            raise WorkspaceStorageError("Could not open local database") from exc

    def save(self, record: WorkspaceInvestigation) -> None:
        try:
            with sqlite_transaction(self._database) as db:
                db.execute(
                    "INSERT OR REPLACE INTO workspace_records(id, updated_at, payload) "
                    "VALUES (?, ?, ?)",
                    (str(record.id), record.updated_at.isoformat(), record.model_dump_json()),
                )
                record_audit(
                    db, action="upsert", resource_type="workspace", resource_id=str(record.id)
                )
        except sqlite3.Error as exc:
            raise WorkspaceStorageError("Could not save local record") from exc

    def load(self, record_id: UUID) -> WorkspaceInvestigation:
        with sqlite_connection(self._database) as db:
            row = db.execute(
                "SELECT payload FROM workspace_records WHERE id = ?", (str(record_id),)
            ).fetchone()
        if row is None:
            raise InvestigationNotFoundError(record_id)
        try:
            return WorkspaceInvestigation.model_validate_json(row[0])
        except ValueError as exc:
            raise WorkspaceStorageError("Corrupt local record") from exc

    def delete(self, record_id: UUID) -> None:
        with sqlite_transaction(self._database) as db:
            cursor = db.execute("DELETE FROM workspace_records WHERE id = ?", (str(record_id),))
            if cursor.rowcount == 0:
                raise InvestigationNotFoundError(record_id)
            record_audit(db, action="delete", resource_type="workspace", resource_id=str(record_id))

    def list_all(self) -> list[WorkspaceInvestigation]:
        with sqlite_connection(self._database) as db:
            rows = db.execute(
                "SELECT payload FROM workspace_records ORDER BY updated_at DESC"
            ).fetchall()
        records: list[WorkspaceInvestigation] = []
        for row in rows:
            try:
                records.append(WorkspaceInvestigation.model_validate_json(row[0]))
            except ValueError:
                continue
        return records

    def exists(self, record_id: UUID) -> bool:
        with sqlite_connection(self._database) as db:
            return (
                db.execute(
                    "SELECT 1 FROM workspace_records WHERE id = ?", (str(record_id),)
                ).fetchone()
                is not None
            )

    def lock(self) -> AbstractContextManager[None]:
        return personal_sqlite_lock(self._database)
