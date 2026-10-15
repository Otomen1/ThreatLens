"""Operation-scoped connections and reentrant personal-record transactions."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from .sqlite_storage import connect, transaction

PERSONAL_LOCK_KEY = 641516225334133
_connections: ContextVar[dict[str, Any] | None] = ContextVar("record_connections", default=None)


def _postgres_key(url: str) -> str:
    return "pg:" + hashlib.sha256(url.encode()).hexdigest()


@contextmanager
def postgres_connection(driver: Any, url: str) -> Iterator[Any]:
    active = (_connections.get() or {}).get(_postgres_key(url))
    if active is not None:
        yield active
    else:
        with driver.connect(url) as db:
            yield db


@contextmanager
def postgres_transaction(driver: Any, url: str) -> Iterator[Any]:
    key = _postgres_key(url)
    existing = _connections.get() or {}
    if key in existing:
        yield existing[key]
        return
    with postgres_connection(driver, url) as db:
        db.execute("SELECT pg_advisory_xact_lock(%s)", (PERSONAL_LOCK_KEY,))
        token = _connections.set({**existing, key: db})
        try:
            yield db
        finally:
            _connections.reset(token)


@contextmanager
def personal_postgres_lock(driver: Any, url: str) -> Iterator[None]:
    with postgres_transaction(driver, url):
        yield


@contextmanager
def sqlite_connection(path: Path) -> Iterator[sqlite3.Connection]:
    key = "sqlite:" + str(path.resolve()).casefold()
    active = (_connections.get() or {}).get(key)
    if active is not None:
        yield active
    else:
        with closing(connect(path)) as db:
            yield db


@contextmanager
def sqlite_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    key = "sqlite:" + str(path.resolve()).casefold()
    existing = _connections.get() or {}
    if key in existing:
        yield existing[key]
        return
    with sqlite_connection(path) as db, transaction(db):
        token = _connections.set({**existing, key: db})
        try:
            yield db
        finally:
            _connections.reset(token)


@contextmanager
def personal_sqlite_lock(path: Path) -> Iterator[None]:
    with sqlite_transaction(path):
        yield
