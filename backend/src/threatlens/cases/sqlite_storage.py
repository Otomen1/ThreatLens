"""Operation-scoped SQLite cases storage; safe across request threads."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from pathlib import Path
from uuid import UUID

from ..record_database import personal_sqlite_lock, sqlite_connection, sqlite_transaction
from ..sqlite_storage import record_audit
from .exceptions import CaseNotFoundError, CaseStorageError
from .models import Case
from .storage import CaseStorage


class SQLiteCaseStorage(CaseStorage):
    def __init__(self, database: Path) -> None:
        self._database = database
        try:
            with sqlite_connection(database):
                pass
        except (OSError, sqlite3.Error) as exc:
            raise CaseStorageError("Could not open local database") from exc

    def save(self, record: Case) -> None:
        try:
            with sqlite_transaction(self._database) as db:
                db.execute(
                    "INSERT OR REPLACE INTO case_records(id, updated_at, payload) VALUES (?, ?, ?)",
                    (str(record.id), record.updated_at.isoformat(), record.model_dump_json()),
                )
                record_audit(db, action="upsert", resource_type="case", resource_id=str(record.id))
        except sqlite3.Error as exc:
            raise CaseStorageError("Could not save local record") from exc

    def load(self, record_id: UUID) -> Case:
        with sqlite_connection(self._database) as db:
            row = db.execute(
                "SELECT payload FROM case_records WHERE id = ?", (str(record_id),)
            ).fetchone()
        if row is None:
            raise CaseNotFoundError(record_id)
        try:
            return Case.model_validate_json(row[0])
        except ValueError as exc:
            raise CaseStorageError("Corrupt local record") from exc

    def delete(self, record_id: UUID) -> None:
        with sqlite_transaction(self._database) as db:
            cursor = db.execute("DELETE FROM case_records WHERE id = ?", (str(record_id),))
            if cursor.rowcount == 0:
                raise CaseNotFoundError(record_id)
            record_audit(db, action="delete", resource_type="case", resource_id=str(record_id))

    def list_all(self) -> list[Case]:
        with sqlite_connection(self._database) as db:
            rows = db.execute(
                "SELECT payload FROM case_records ORDER BY updated_at DESC"
            ).fetchall()
        records: list[Case] = []
        for row in rows:
            try:
                records.append(Case.model_validate_json(row[0]))
            except ValueError:
                continue
        return records

    def exists(self, record_id: UUID) -> bool:
        with sqlite_connection(self._database) as db:
            return (
                db.execute("SELECT 1 FROM case_records WHERE id = ?", (str(record_id),)).fetchone()
                is not None
            )

    def lock(self) -> AbstractContextManager[None]:
        return personal_sqlite_lock(self._database)
