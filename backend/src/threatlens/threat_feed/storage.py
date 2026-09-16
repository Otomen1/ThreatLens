"""PostgreSQL, SQLite, and in-memory persistence for Threat Feed records."""

from __future__ import annotations

import importlib
import os
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from .models import FeedRefreshResult, FeedSourceStatus, ThreatFeedItem


@dataclass(frozen=True)
class FeedStorageSnapshot:
    items: tuple[ThreatFeedItem, ...]
    sources: tuple[FeedSourceStatus, ...]
    last_refresh: str | None


class FeedStorage:
    def __init__(self) -> None:
        self.backend = os.getenv("THREATLENS_STORAGE_BACKEND", "file").lower()
        self.url = os.getenv("DATABASE_URL", "")
        self.path = Path(os.getenv("THREATLENS_DATABASE_PATH", "data/threatlens.db"))
        self.memory_items: dict[str, ThreatFeedItem] = {}
        self.memory_sources: dict[str, FeedSourceStatus] = {}
        self.memory_state: dict[str, str] = {}
        self.psycopg: Any | None = None
        self._init()

    def _init(self) -> None:
        if self.backend == "postgres" and self.url:
            self.psycopg = cast(Any, importlib.import_module("psycopg"))
            with self.psycopg.connect(self.url) as db:
                self._schema(db, postgres=True)
        elif self.backend == "sqlite":
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path) as db:
                self._schema(db, postgres=False)

    @staticmethod
    def _schema(db: Any, *, postgres: bool) -> None:
        json_type = "jsonb" if postgres else "text"
        db.execute(
            "CREATE TABLE IF NOT EXISTS threat_feed_items("
            f"id text PRIMARY KEY,published_at text NOT NULL,payload {json_type} NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS threat_feed_sources("
            f"id text PRIMARY KEY,payload {json_type} NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS threat_feed_state(key text PRIMARY KEY,value text NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS threat_feed_refresh_runs("
            f"id text PRIMARY KEY,started_at text NOT NULL,payload {json_type} NOT NULL)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS threat_feed_items_published_idx "
            "ON threat_feed_items(published_at DESC)"
        )

    def save_items(self, items: Iterable[ThreatFeedItem]) -> int:
        candidates = list(items)
        if not candidates:
            return 0
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                existing = {
                    str(row[0])
                    for row in db.execute("SELECT id FROM threat_feed_items").fetchall()
                }
                new_items = [item for item in candidates if item.id not in existing]
                with db.cursor() as cursor:
                    cursor.executemany(
                        "INSERT INTO threat_feed_items VALUES (%s,%s,%s::jsonb) "
                        "ON CONFLICT DO NOTHING",
                        [
                            (item.id, item.published_at.isoformat(), item.model_dump_json())
                            for item in new_items
                        ],
                    )
            return len(new_items)
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                existing = {
                    str(row[0]) for row in db.execute("SELECT id FROM threat_feed_items").fetchall()
                }
                new_items = [item for item in candidates if item.id not in existing]
                db.executemany(
                    "INSERT OR IGNORE INTO threat_feed_items VALUES (?,?,?)",
                    [
                        (item.id, item.published_at.isoformat(), item.model_dump_json())
                        for item in new_items
                    ],
                )
            return len(new_items)
        new_items = [item for item in candidates if item.id not in self.memory_items]
        self.memory_items.update({item.id: item for item in new_items})
        return len(new_items)

    def list_items(self) -> list[ThreatFeedItem]:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                rows = db.execute(
                    "SELECT payload FROM threat_feed_items ORDER BY published_at DESC"
                ).fetchall()
            return [ThreatFeedItem.model_validate(row[0]) for row in rows]
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                rows = db.execute(
                    "SELECT payload FROM threat_feed_items ORDER BY published_at DESC"
                ).fetchall()
            return [ThreatFeedItem.model_validate_json(row[0]) for row in rows]
        return sorted(self.memory_items.values(), key=lambda item: item.published_at, reverse=True)

    def home_snapshot(self) -> FeedStorageSnapshot:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                rows = db.execute(
                    "SELECT 'item', payload FROM threat_feed_items "
                    "UNION ALL SELECT 'source', payload FROM threat_feed_sources "
                    "UNION ALL SELECT 'state', to_jsonb(value) FROM threat_feed_state "
                    "WHERE key='last_refresh'"
                ).fetchall()
            items = tuple(
                ThreatFeedItem.model_validate(payload)
                for kind, payload in rows
                if kind == "item"
            )
            sources = tuple(
                FeedSourceStatus.model_validate(payload)
                for kind, payload in rows
                if kind == "source"
            )
            refresh = next(
                (str(payload) for kind, payload in rows if kind == "state"), None
            )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                rows = db.execute(
                    "SELECT 'item', payload FROM threat_feed_items "
                    "UNION ALL SELECT 'source', payload FROM threat_feed_sources "
                    "UNION ALL SELECT 'state', value FROM threat_feed_state "
                    "WHERE key='last_refresh'"
                ).fetchall()
            items = tuple(
                ThreatFeedItem.model_validate_json(payload)
                for kind, payload in rows
                if kind == "item"
            )
            sources = tuple(
                FeedSourceStatus.model_validate_json(payload)
                for kind, payload in rows
                if kind == "source"
            )
            refresh = next((str(payload) for kind, payload in rows if kind == "state"), None)
        else:
            items = tuple(self.memory_items.values())
            sources = tuple(self.memory_sources.values())
            refresh = self.memory_state.get("last_refresh")
        return FeedStorageSnapshot(
            items=tuple(sorted(items, key=lambda item: item.published_at, reverse=True)),
            sources=sources,
            last_refresh=refresh,
        )

    def get_item(self, item_id: str) -> ThreatFeedItem | None:
        return next((item for item in self.list_items() if item.id == item_id), None)

    def delete_before(self, cutoff: datetime) -> None:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute(
                    "DELETE FROM threat_feed_items WHERE published_at < %s", (cutoff.isoformat(),)
                )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute(
                    "DELETE FROM threat_feed_items WHERE published_at < ?", (cutoff.isoformat(),)
                )
        else:
            self.memory_items = {
                key: item for key, item in self.memory_items.items() if item.published_at >= cutoff
            }

    def save_source(self, source: FeedSourceStatus) -> None:
        payload = source.model_dump_json()
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute(
                    "INSERT INTO threat_feed_sources VALUES (%s,%s::jsonb) "
                    "ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload",
                    (source.id, payload),
                )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute(
                    "INSERT OR REPLACE INTO threat_feed_sources VALUES (?,?)", (source.id, payload)
                )
        else:
            self.memory_sources[source.id] = source

    def list_sources(self) -> list[FeedSourceStatus]:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                rows = db.execute("SELECT payload FROM threat_feed_sources").fetchall()
            return [FeedSourceStatus.model_validate(row[0]) for row in rows]
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                rows = db.execute("SELECT payload FROM threat_feed_sources").fetchall()
            return [FeedSourceStatus.model_validate_json(row[0]) for row in rows]
        return list(self.memory_sources.values())

    def save_refresh(self, refresh: FeedRefreshResult) -> None:
        refresh_id = refresh.started_at.isoformat()
        payload = refresh.model_dump_json()
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute(
                    "INSERT INTO threat_feed_refresh_runs VALUES (%s,%s,%s::jsonb) "
                    "ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload",
                    (refresh_id, refresh_id, payload),
                )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute(
                    "INSERT OR REPLACE INTO threat_feed_refresh_runs VALUES (?,?,?)",
                    (refresh_id, refresh_id, payload),
                )

    def state(self, key: str) -> str | None:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                row = db.execute(
                    "SELECT value FROM threat_feed_state WHERE key=%s", (key,)
                ).fetchone()
            return str(row[0]) if row else None
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                row = db.execute(
                    "SELECT value FROM threat_feed_state WHERE key=?", (key,)
                ).fetchone()
            return str(row[0]) if row else None
        return self.memory_state.get(key)

    def set_state(self, key: str, value: str) -> None:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute(
                    "INSERT INTO threat_feed_state VALUES (%s,%s) "
                    "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                    (key, value),
                )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute("INSERT OR REPLACE INTO threat_feed_state VALUES (?,?)", (key, value))
        else:
            self.memory_state[key] = value
