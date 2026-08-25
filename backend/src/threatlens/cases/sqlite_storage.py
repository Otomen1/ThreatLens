"""SQLite implementation of the CaseStorage contract."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from uuid import UUID

from ..sqlite_storage import connect, record_audit, transaction
from .exceptions import CaseNotFoundError, CaseStorageError
from .models import Case
from .storage import CaseStorage


class SQLiteCaseStorage(CaseStorage):
    def __init__(self, database: Path) -> None:
        try:
            self._db = connect(database)
        except (OSError, sqlite3.Error) as exc:
            raise CaseStorageError(f"Could not open SQLite database: {database}") from exc

    def save(self, case: Case) -> None:
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO case_records(id, updated_at, payload) VALUES (?, ?, ?)",
                (str(case.id), case.updated_at.isoformat(), case.model_dump_json()),
            )
            record_audit(self._db, action="upsert", resource_type="case", resource_id=str(case.id))
        except sqlite3.Error as exc:
            raise CaseStorageError(f"Could not save case {case.id}") from exc

    def load(self, case_id: UUID) -> Case:
        row = self._db.execute("SELECT payload FROM case_records WHERE id = ?", (str(case_id),)).fetchone()
        if row is None:
            raise CaseNotFoundError(case_id)
        try:
            return Case.model_validate_json(row[0])
        except ValueError as exc:
            raise CaseStorageError(f"Corrupt case record: {case_id}") from exc

    def delete(self, case_id: UUID) -> None:
        cursor = self._db.execute("DELETE FROM case_records WHERE id = ?", (str(case_id),))
        if cursor.rowcount == 0:
            raise CaseNotFoundError(case_id)
        record_audit(self._db, action="delete", resource_type="case", resource_id=str(case_id))

    def list_all(self) -> list[Case]:
        rows = self._db.execute("SELECT payload FROM case_records ORDER BY updated_at DESC").fetchall()
        records: list[Case] = []
        for row in rows:
            try:
                records.append(Case.model_validate_json(row[0]))
            except ValueError:
                continue
        return records

    def exists(self, case_id: UUID) -> bool:
        return self._db.execute("SELECT 1 FROM case_records WHERE id = ?", (str(case_id),)).fetchone() is not None

    def lock(self):
        return transaction(self._db)
