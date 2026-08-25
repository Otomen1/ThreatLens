"""SQLite implementation of the WorkspaceStorage contract."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from uuid import UUID

from ..sqlite_storage import connect, record_audit, transaction
from .exceptions import InvestigationNotFoundError, WorkspaceStorageError
from .models import WorkspaceInvestigation
from .storage import WorkspaceStorage


class SQLiteWorkspaceStorage(WorkspaceStorage):
    def __init__(self, database: Path) -> None:
        self._database = database
        try:
            self._db = connect(database)
        except (OSError, sqlite3.Error) as exc:
            raise WorkspaceStorageError(f"Could not open SQLite database: {database}") from exc

    def save(self, record: WorkspaceInvestigation) -> None:
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO workspace_records(id, updated_at, payload) VALUES (?, ?, ?)",
                (str(record.id), record.updated_at.isoformat(), record.model_dump_json()),
            )
            record_audit(self._db, action="upsert", resource_type="workspace", resource_id=str(record.id))
        except sqlite3.Error as exc:
            raise WorkspaceStorageError(f"Could not save investigation {record.id}") from exc

    def load(self, investigation_id: UUID) -> WorkspaceInvestigation:
        row = self._db.execute("SELECT payload FROM workspace_records WHERE id = ?", (str(investigation_id),)).fetchone()
        if row is None:
            raise InvestigationNotFoundError(investigation_id)
        try:
            return WorkspaceInvestigation.model_validate_json(row[0])
        except ValueError as exc:
            raise WorkspaceStorageError(f"Corrupt investigation record: {investigation_id}") from exc

    def delete(self, investigation_id: UUID) -> None:
        cursor = self._db.execute("DELETE FROM workspace_records WHERE id = ?", (str(investigation_id),))
        if cursor.rowcount == 0:
            raise InvestigationNotFoundError(investigation_id)
        record_audit(self._db, action="delete", resource_type="workspace", resource_id=str(investigation_id))

    def list_all(self) -> list[WorkspaceInvestigation]:
        rows = self._db.execute("SELECT payload FROM workspace_records ORDER BY updated_at DESC").fetchall()
        records: list[WorkspaceInvestigation] = []
        for row in rows:
            try:
                records.append(WorkspaceInvestigation.model_validate_json(row[0]))
            except ValueError:
                continue
        return records

    def exists(self, investigation_id: UUID) -> bool:
        return self._db.execute("SELECT 1 FROM workspace_records WHERE id = ?", (str(investigation_id),)).fetchone() is not None

    def lock(self):
        return transaction(self._db)
