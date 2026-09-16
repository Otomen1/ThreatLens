"""Best-effort durable provider telemetry using existing free storage."""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, cast


def load_state() -> tuple[dict[str, dict[str, str | int | None]], list[dict[str, Any]]]:
    try:
        backend = os.getenv("THREATLENS_STORAGE_BACKEND", "file").lower()
        if backend == "postgres" and os.getenv("DATABASE_URL"):
            psycopg = cast(Any, importlib.import_module("psycopg"))
            with psycopg.connect(os.environ["DATABASE_URL"]) as connection:
                _init_postgres(connection)
                rows = connection.execute(
                    "SELECT provider,payload FROM threatlens_provider_state"
                ).fetchall()
                events = connection.execute(
                    "SELECT payload FROM threatlens_provider_events "
                    "ORDER BY occurred_at DESC LIMIT 500"
                ).fetchall()
            return (
                {row[0]: dict(row[1]) for row in rows},
                [dict(row[0]) for row in reversed(events)],
            )
        if backend == "sqlite":
            path = Path(os.getenv("THREATLENS_DATABASE_PATH", "data/threatlens.db"))
            path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(path) as connection:
                _init_sqlite(connection)
                rows = connection.execute("SELECT provider,payload FROM provider_state").fetchall()
                events = connection.execute(
                    "SELECT payload FROM provider_events ORDER BY id DESC LIMIT 500"
                ).fetchall()
            return (
                {row[0]: json.loads(row[1]) for row in rows},
                [json.loads(row[0]) for row in reversed(events)],
            )
    except Exception:
        pass
    return {}, []


def save_event(provider: str, quota: dict[str, Any], event: dict[str, Any]) -> None:
    try:
        backend = os.getenv("THREATLENS_STORAGE_BACKEND", "file").lower()
        if backend == "postgres" and os.getenv("DATABASE_URL"):
            psycopg = cast(Any, importlib.import_module("psycopg"))
            with psycopg.connect(os.environ["DATABASE_URL"]) as connection:
                _init_postgres(connection)
                connection.execute(
                    "INSERT INTO threatlens_provider_state(provider,payload) "
                    "VALUES (%s,%s::jsonb) ON CONFLICT(provider) "
                    "DO UPDATE SET payload=EXCLUDED.payload",
                    (provider, json.dumps(quota)),
                )
                connection.execute(
                    "INSERT INTO threatlens_provider_events(occurred_at,payload) "
                    "VALUES (%s,%s::jsonb)",
                    (event["timestamp"], json.dumps(event)),
                )
                connection.execute(
                    "DELETE FROM threatlens_provider_events WHERE id NOT IN "
                    "(SELECT id FROM threatlens_provider_events ORDER BY id DESC LIMIT 500)"
                )
        elif backend == "sqlite":
            path = Path(os.getenv("THREATLENS_DATABASE_PATH", "data/threatlens.db"))
            path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(path) as connection:
                _init_sqlite(connection)
                connection.execute(
                    "INSERT OR REPLACE INTO provider_state VALUES (?,?)",
                    (provider, json.dumps(quota)),
                )
                connection.execute(
                    "INSERT INTO provider_events(payload) VALUES (?)", (json.dumps(event),)
                )
                connection.execute(
                    "DELETE FROM provider_events WHERE id NOT IN "
                    "(SELECT id FROM provider_events ORDER BY id DESC LIMIT 500)"
                )
    except Exception:
        pass


def _init_postgres(connection: Any) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS threatlens_provider_state("
        "provider text PRIMARY KEY,payload jsonb NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS threatlens_provider_events("
        "id bigserial PRIMARY KEY,occurred_at timestamptz NOT NULL,"
        "payload jsonb NOT NULL)"
    )


def _init_sqlite(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS provider_state(provider TEXT PRIMARY KEY,payload TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS provider_events("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL)"
    )
