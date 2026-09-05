"""PostgreSQL Case storage for serverless deployments."""

from __future__ import annotations

import importlib
import os
from contextlib import AbstractContextManager, nullcontext
from typing import Any, cast
from uuid import UUID

from pydantic import ValidationError

from .exceptions import CaseNotFoundError, CaseStorageError
from .models import Case
from .storage import CaseStorage


class PostgresCaseStorage(CaseStorage):
    def __init__(self, url: str | None = None) -> None:
        self._url = url or os.environ.get("DATABASE_URL", "")
        if not self._url:
            raise CaseStorageError("DATABASE_URL is required for postgres case storage")
        try:
            psycopg = cast(Any, importlib.import_module("psycopg"))
            self._psycopg = psycopg
            with psycopg.connect(self._url) as connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS threatlens_case_records (
                    id uuid PRIMARY KEY,
                    updated_at timestamptz NOT NULL,
                    payload jsonb NOT NULL
                    )"""
                )
        except Exception as exc:
            raise CaseStorageError("Could not initialize PostgreSQL case storage") from exc

    def save(self, case: Case) -> None:
        try:
            with self._psycopg.connect(self._url) as connection:
                connection.execute(
                    """INSERT INTO threatlens_case_records (id, updated_at, payload)
                    VALUES (%s, %s, %s::jsonb)
                    ON CONFLICT (id) DO UPDATE SET
                    updated_at = EXCLUDED.updated_at, payload = EXCLUDED.payload""",
                    (case.id, case.updated_at, case.model_dump_json()),
                )
        except Exception as exc:
            raise CaseStorageError(f"Could not save case {case.id}") from exc

    def load(self, case_id: UUID) -> Case:
        try:
            with self._psycopg.connect(self._url) as connection:
                row = connection.execute(
                    "SELECT payload FROM threatlens_case_records WHERE id = %s", (case_id,)
                ).fetchone()
        except Exception as exc:
            raise CaseStorageError("Could not load case") from exc
        if row is None:
            raise CaseNotFoundError(case_id)
        try:
            return Case.model_validate(row[0])
        except ValidationError as exc:
            raise CaseStorageError(f"Corrupt case record: {case_id}") from exc

    def delete(self, case_id: UUID) -> None:
        with self._psycopg.connect(self._url) as connection:
            result = connection.execute(
                "DELETE FROM threatlens_case_records WHERE id = %s", (case_id,)
            )
            if result.rowcount == 0:
                raise CaseNotFoundError(case_id)

    def list_all(self) -> list[Case]:
        with self._psycopg.connect(self._url) as connection:
            rows = connection.execute(
                "SELECT payload FROM threatlens_case_records ORDER BY updated_at DESC"
            ).fetchall()
        return [Case.model_validate(row[0]) for row in rows]

    def exists(self, case_id: UUID) -> bool:
        with self._psycopg.connect(self._url) as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM threatlens_case_records WHERE id = %s", (case_id,)
                ).fetchone()
                is not None
            )

    def lock(self) -> AbstractContextManager[None]:
        return nullcontext()
