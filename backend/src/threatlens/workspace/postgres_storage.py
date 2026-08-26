"""PostgreSQL implementation of the WorkspaceStorage contract."""

from __future__ import annotations

import os
from contextlib import nullcontext
from uuid import UUID

from pydantic import ValidationError

from .exceptions import InvestigationNotFoundError, WorkspaceStorageError
from .models import WorkspaceInvestigation
from .storage import WorkspaceStorage


class PostgresWorkspaceStorage(WorkspaceStorage):
    """Small stateless adapter suited to serverless PostgreSQL connections."""

    def __init__(self, url: str | None = None) -> None:
        self._url = url or os.environ.get("DATABASE_URL", "")
        if not self._url:
            raise WorkspaceStorageError("DATABASE_URL is required for postgres storage")
        try:
            import psycopg
            self._psycopg = psycopg
            with self._psycopg.connect(self._url) as connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS threatlens_workspace_records (
                        id uuid PRIMARY KEY,
                        updated_at timestamptz NOT NULL,
                        payload jsonb NOT NULL
                    )
                """)
        except Exception as exc:
            raise WorkspaceStorageError("Could not initialize PostgreSQL workspace storage") from exc

    def save(self, record: WorkspaceInvestigation) -> None:
        try:
            with self._psycopg.connect(self._url) as connection:
                connection.execute("""
                    INSERT INTO threatlens_workspace_records (id, updated_at, payload)
                    VALUES (%s, %s, %s::jsonb)
                    ON CONFLICT (id) DO UPDATE SET updated_at = EXCLUDED.updated_at, payload = EXCLUDED.payload
                """, (record.id, record.updated_at, record.model_dump_json()))
        except Exception as exc:
            raise WorkspaceStorageError(f"Could not save investigation {record.id}") from exc

    def load(self, investigation_id: UUID) -> WorkspaceInvestigation:
        try:
            with self._psycopg.connect(self._url) as connection:
                row = connection.execute("SELECT payload FROM threatlens_workspace_records WHERE id = %s", (investigation_id,)).fetchone()
        except Exception as exc:
            raise WorkspaceStorageError("Could not load investigation") from exc
        if row is None:
            raise InvestigationNotFoundError(investigation_id)
        try:
            return WorkspaceInvestigation.model_validate(row[0])
        except ValidationError as exc:
            raise WorkspaceStorageError(f"Corrupt investigation record: {investigation_id}") from exc

    def delete(self, investigation_id: UUID) -> None:
        try:
            with self._psycopg.connect(self._url) as connection:
                result = connection.execute("DELETE FROM threatlens_workspace_records WHERE id = %s", (investigation_id,))
                if result.rowcount == 0:
                    raise InvestigationNotFoundError(investigation_id)
        except InvestigationNotFoundError:
            raise
        except Exception as exc:
            raise WorkspaceStorageError("Could not delete investigation") from exc

    def list_all(self) -> list[WorkspaceInvestigation]:
        try:
            with self._psycopg.connect(self._url) as connection:
                rows = connection.execute("SELECT payload FROM threatlens_workspace_records ORDER BY updated_at DESC").fetchall()
            return [WorkspaceInvestigation.model_validate(row[0]) for row in rows]
        except ValidationError as exc:
            raise WorkspaceStorageError("Corrupt investigation record") from exc
        except Exception as exc:
            raise WorkspaceStorageError("Could not list investigations") from exc

    def exists(self, investigation_id: UUID) -> bool:
        with self._psycopg.connect(self._url) as connection:
            return connection.execute("SELECT 1 FROM threatlens_workspace_records WHERE id = %s", (investigation_id,)).fetchone() is not None

    def lock(self):
        return nullcontext()
