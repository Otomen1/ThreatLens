"""Atomic owner request counters shared by serverless instances; no paid store."""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any, cast

from ..atomic_file import atomic_write
from ..storage_lock import file_lock


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    retry_after: int


class RequestLimiter:
    def __init__(self, backend: str, url: str, database: str, filename: str) -> None:
        self.backend, self.url = backend, url
        self.database, self.filename = Path(database), Path(filename)
        self.memory: dict[str, tuple[int, int]] = {}
        self.guard = Lock()
        self.initialized = False

    def consume(self, key: str, limit: int, *, now: float | None = None) -> LimitResult:
        stamp = time.time() if now is None else now
        window = int(stamp // 60) * 60
        retry = max(1, int(window + 60 - stamp + 0.999))
        if limit <= 0:
            return LimitResult(True, 0)
        self._prepare()
        if self.backend == "postgres":
            if not self.url:
                raise RuntimeError("Request-limit storage is unavailable")
            psycopg = cast(Any, importlib.import_module("psycopg"))
            with psycopg.connect(self.url) as db:
                row = db.execute(
                    "INSERT INTO threatlens_request_limits(key,window_start,requests) "
                    "VALUES (%s,%s,1) ON CONFLICT(key) DO UPDATE SET "
                    "window_start=EXCLUDED.window_start, requests=CASE "
                    "WHEN threatlens_request_limits.window_start=EXCLUDED.window_start "
                    "THEN threatlens_request_limits.requests+1 ELSE 1 END "
                    "WHERE threatlens_request_limits.window_start<>EXCLUDED.window_start "
                    "OR threatlens_request_limits.requests<%s RETURNING requests",
                    (key, window, limit),
                ).fetchone()
                db.execute(
                    "DELETE FROM threatlens_request_limits WHERE window_start<%s", (window - 3600,)
                )
            return LimitResult(row is not None, retry)
        if self.backend == "sqlite":
            self.database.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(self.database, timeout=10)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT window_start,requests FROM threatlens_request_limits WHERE key=?",
                    (key,),
                ).fetchone()
                used = int(row[1]) if row and row[0] == window else 0
                if used >= limit:
                    return LimitResult(False, retry)
                db.execute(
                    "INSERT OR REPLACE INTO threatlens_request_limits VALUES (?,?,?)",
                    (key, window, used + 1),
                )
                db.execute(
                    "DELETE FROM threatlens_request_limits WHERE window_start<?", (window - 3600,)
                )
            return LimitResult(True, retry)
        if self.backend == "memory":
            with self.guard:
                prior, used = self.memory.get(key, (window, 0))
                used = used if prior == window else 0
                if used >= limit:
                    return LimitResult(False, retry)
                self.memory = {k: v for k, v in self.memory.items() if v[0] >= window - 3600}
                self.memory[key] = (window, used + 1)
                return LimitResult(True, retry)
        with file_lock(self.filename.with_suffix(".lock")):
            try:
                state = (
                    json.loads(self.filename.read_text(encoding="utf-8"))
                    if self.filename.exists()
                    else {}
                )
                prior, used = state.get(key, [window, 0])
                used = int(used) if prior == window else 0
                if used >= limit:
                    return LimitResult(False, retry)
                state = {k: v for k, v in state.items() if v[0] >= window - 3600}
                state[key] = [window, used + 1]
                atomic_write(self.filename, json.dumps(state))
                return LimitResult(True, retry)
            except (ValueError, TypeError, AttributeError) as exc:
                raise RuntimeError("Request-limit storage is unavailable") from exc

    def _prepare(self) -> None:
        if self.backend not in {"postgres", "sqlite"} or self.initialized:
            return
        with self.guard:
            if self.initialized:
                return
            if self.backend == "postgres":
                if not self.url:
                    raise RuntimeError("Request-limit storage is unavailable")
                driver = cast(Any, importlib.import_module("psycopg"))
                with driver.connect(self.url) as db:
                    self._schema(db, postgres=True)
            else:
                self.database.parent.mkdir(parents=True, exist_ok=True)
                with closing(sqlite3.connect(self.database, timeout=10)) as db, db:
                    self._schema(db, postgres=False)
            self.initialized = True

    @staticmethod
    def _schema(db: Any, *, postgres: bool) -> None:
        db.execute(
            "CREATE TABLE IF NOT EXISTS threatlens_request_limits("
            "key text PRIMARY KEY,window_start bigint NOT NULL,requests bigint NOT NULL)"
        )
        if postgres:
            db.execute("ALTER TABLE threatlens_request_limits ENABLE ROW LEVEL SECURITY")


@lru_cache(maxsize=8)
def _limiter(backend: str, url: str, database: str, filename: str) -> RequestLimiter:
    return RequestLimiter(backend, url, database, filename)


def consume_owner_request(user_id: str, scope: str = "private", limit: int = 60) -> LimitResult:
    limiter = _limiter(
        os.getenv("THREATLENS_STORAGE_BACKEND", "file").lower(),
        os.getenv("DATABASE_URL", ""),
        os.getenv("THREATLENS_DATABASE_PATH", "data/threatlens.db"),
        os.getenv("THREATLENS_RATE_LIMIT_PATH", "data/request-limits.json"),
    )
    return limiter.consume(f"{user_id}:{scope}", limit)
