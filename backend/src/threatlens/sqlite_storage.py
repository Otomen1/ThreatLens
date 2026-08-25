"""Small SQLite foundation shared by durable Workspace and Case storage.

The schema is intentionally JSON-in-row: Pydantic remains the canonical domain
model while SQLite supplies durable atomic storage, indexing, and transactions.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Iterator


SCHEMA_VERSION = 1


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    migrate(db)
    return db


def migrate(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = db.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if row is None:
        db.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
    elif row[0] > SCHEMA_VERSION:
        raise RuntimeError("database schema is newer than this ThreatLens build")
    db.execute("""CREATE TABLE IF NOT EXISTS workspace_records (
        id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, payload TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_workspace_updated ON workspace_records(updated_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS case_records (
        id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, payload TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_case_updated ON case_records(updated_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
        actor TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL,
        resource_id TEXT, detail TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource_type, resource_id)")


def record_audit(
    db: sqlite3.Connection,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None,
    detail: dict[str, object] | None = None,
) -> None:
    """Append a durable audit event for a storage mutation."""
    db.execute(
        "INSERT INTO audit_events(occurred_at, actor, action, resource_type, resource_id, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now(UTC).isoformat(), "system", action, resource_type, resource_id, json.dumps(detail or {})),
    )


@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    else:
        db.commit()
