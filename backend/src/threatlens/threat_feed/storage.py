"""PostgreSQL, SQLite, and in-memory persistence for Threat Feed records."""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, cast

from .models import FeedRefreshResult, FeedSourceStatus, FeedVulnerability, ThreatFeedItem


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
        self.memory_vulnerabilities: dict[str, FeedVulnerability] = {}
        self._lease_lock = Lock()
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
            "CREATE TABLE IF NOT EXISTS threat_feed_vulnerabilities("
            f"id text PRIMARY KEY,activity_at text NOT NULL,payload {json_type} NOT NULL)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS threat_feed_vulnerability_activity_idx "
            "ON threat_feed_vulnerabilities(activity_at DESC)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS threat_feed_refresh_lease("
            "id text PRIMARY KEY,owner text NOT NULL,expires_at double precision NOT NULL)"
        )
        if postgres:
            db.execute("ALTER TABLE threat_feed_vulnerabilities ENABLE ROW LEVEL SECURITY")
            db.execute("ALTER TABLE threat_feed_refresh_lease ENABLE ROW LEVEL SECURITY")
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
                rows = db.execute(
                    "INSERT INTO threat_feed_items(id,published_at,payload) "
                    "SELECT id,published_at,payload::jsonb FROM "
                    "unnest(%s::text[],%s::text[],%s::text[]) "
                    "AS batch(id,published_at,payload) ON CONFLICT DO NOTHING RETURNING id",
                    (
                        [item.id for item in candidates],
                        [item.published_at.isoformat() for item in candidates],
                        [item.model_dump_json() for item in candidates],
                    ),
                ).fetchall()
            return len(rows)
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                before = db.total_changes
                db.executemany(
                    "INSERT OR IGNORE INTO threat_feed_items VALUES (?,?,?)",
                    [
                        (item.id, item.published_at.isoformat(), item.model_dump_json())
                        for item in candidates
                    ],
                )
                inserted = db.total_changes - before
            return inserted
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
                ThreatFeedItem.model_validate(payload) for kind, payload in rows if kind == "item"
            )
            sources = tuple(
                FeedSourceStatus.model_validate(payload)
                for kind, payload in rows
                if kind == "source"
            )
            refresh = next((str(payload) for kind, payload in rows if kind == "state"), None)
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
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                row = db.execute(
                    "SELECT payload FROM threat_feed_items WHERE id=%s", (item_id,)
                ).fetchone()
            return ThreatFeedItem.model_validate(row[0]) if row else None
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                row = db.execute(
                    "SELECT payload FROM threat_feed_items WHERE id=?", (item_id,)
                ).fetchone()
            return ThreatFeedItem.model_validate_json(row[0]) if row else None
        return self.memory_items.get(item_id)

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

    def reserve_poc_source(
        self, source: str, owner: str, now: datetime, *, release: bool = False
    ) -> tuple[bool, bool, datetime | None]:
        """Atomic source-wide lease/cooldown using two existing operational state keys."""
        if source not in {"metasploit", "nuclei"}:
            raise ValueError("Unknown PoC source")
        key = f"poc_source:{source}"
        stamp = now.timestamp()

        def update(raw: str) -> tuple[str, tuple[bool, bool, datetime | None]]:
            state = json.loads(raw)
            attempt = float(state.get("attempt", 0))
            expiry = float(state.get("expiry", 0))
            if release:
                if state.get("owner") == owner:
                    state.update(owner="", expiry=0)
                return json.dumps(state), (False, False, None)
            next_at = datetime.fromtimestamp(max(expiry, attempt + 60), UTC)
            if expiry > stamp or attempt + 60 > stamp:
                return raw, (False, expiry > stamp, next_at)
            state.update(owner=owner, expiry=stamp + 30, attempt=stamp)
            return json.dumps(state), (True, False, datetime.fromtimestamp(stamp + 60, UTC))

        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute(
                    "INSERT INTO threat_feed_state VALUES (%s,'{}') ON CONFLICT(key) DO NOTHING",
                    (key,),
                )
                row = db.execute(
                    "SELECT value FROM threat_feed_state WHERE key=%s FOR UPDATE", (key,)
                ).fetchone()
                value, result = update(row[0])
                db.execute("UPDATE threat_feed_state SET value=%s WHERE key=%s", (value, key))
                return result
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT value FROM threat_feed_state WHERE key=?", (key,)
                ).fetchone()
                value, result = update(row[0] if row else "{}")
                db.execute("INSERT OR REPLACE INTO threat_feed_state VALUES (?,?)", (key, value))
                return result
        with self._lease_lock:
            value, result = update(self.memory_state.get(key, "{}"))
            self.memory_state[key] = value
            return result

    def acquire_refresh(self, owner: str, now: datetime, *, force: bool) -> bool:
        """Atomically reserve collection and check the durable cooldown."""
        stamp = now.timestamp()
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                row = db.execute(
                    "INSERT INTO threat_feed_refresh_lease VALUES ('global',%s,%s) "
                    "ON CONFLICT(id) DO UPDATE SET owner=EXCLUDED.owner,"
                    "expires_at=EXCLUDED.expires_at "
                    "WHERE threat_feed_refresh_lease.expires_at <= %s RETURNING owner",
                    (owner, stamp + 240, stamp),
                ).fetchone()
                if row is None:
                    return False
                last = db.execute(
                    "SELECT value FROM threat_feed_state "
                    "WHERE key IN ('last_refresh','last_refresh_attempt') "
                    "ORDER BY value DESC LIMIT 1"
                ).fetchone()
                if (
                    not force
                    and last
                    and stamp < datetime.fromisoformat(last[0]).timestamp() + 1800
                ):
                    db.execute("DELETE FROM threat_feed_refresh_lease WHERE owner=%s", (owner,))
                    return False
                db.execute(
                    "INSERT INTO threat_feed_state VALUES ('last_refresh_attempt',%s) "
                    "ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                    (now.isoformat(),),
                )
                return True
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute("BEGIN IMMEDIATE")
                lease = db.execute(
                    "SELECT expires_at FROM threat_feed_refresh_lease WHERE id='global'"
                ).fetchone()
                last = db.execute(
                    "SELECT value FROM threat_feed_state "
                    "WHERE key IN ('last_refresh','last_refresh_attempt') "
                    "ORDER BY value DESC LIMIT 1"
                ).fetchone()
                if lease and lease[0] > stamp:
                    return False
                if (
                    not force
                    and last
                    and stamp < datetime.fromisoformat(last[0]).timestamp() + 1800
                ):
                    return False
                db.execute(
                    "INSERT OR REPLACE INTO threat_feed_refresh_lease VALUES ('global',?,?)",
                    (owner, stamp + 240),
                )
                db.execute(
                    "INSERT OR REPLACE INTO threat_feed_state VALUES ('last_refresh_attempt',?)",
                    (now.isoformat(),),
                )
                return True
        with self._lease_lock:
            expires = float(self.memory_state.get("lease_expiry", "0"))
            last_value = self.memory_state.get("last_refresh_attempt") or self.memory_state.get(
                "last_refresh"
            )
            if expires > stamp:
                return False
            if (
                not force
                and last_value
                and stamp < datetime.fromisoformat(last_value).timestamp() + 1800
            ):
                return False
            self.memory_state.update(lease_owner=owner, lease_expiry=str(stamp + 240))
            self.memory_state["last_refresh_attempt"] = now.isoformat()
            return True

    def release_refresh(self, owner: str) -> None:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute("DELETE FROM threat_feed_refresh_lease WHERE owner=%s", (owner,))
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute("DELETE FROM threat_feed_refresh_lease WHERE owner=?", (owner,))
        else:
            with self._lease_lock:
                if self.memory_state.get("lease_owner") == owner:
                    self.memory_state.pop("lease_owner", None)
                    self.memory_state.pop("lease_expiry", None)

    def list_vulnerabilities(self) -> list[FeedVulnerability]:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                rows = db.execute("SELECT payload FROM threat_feed_vulnerabilities").fetchall()
            return [FeedVulnerability.model_validate(row[0]) for row in rows]
        if self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                rows = db.execute("SELECT payload FROM threat_feed_vulnerabilities").fetchall()
            return [FeedVulnerability.model_validate_json(row[0]) for row in rows]
        return list(self.memory_vulnerabilities.values())

    def save_vulnerabilities(
        self, records: Iterable[FeedVulnerability], *, state: dict[str, str] | None = None
    ) -> None:
        """Commit a source page and its synchronization cursor in one transaction."""
        values = [(r.id, r.activity_at.isoformat(), r.model_dump_json()) for r in records]
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db, db.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO threat_feed_vulnerabilities VALUES (%s,%s,%s::jsonb) "
                    "ON CONFLICT(id) DO UPDATE SET activity_at=EXCLUDED.activity_at,"
                    "payload=EXCLUDED.payload",
                    values,
                )
                cursor.executemany(
                    "INSERT INTO threat_feed_state VALUES (%s,%s) ON CONFLICT(key) "
                    "DO UPDATE SET value=EXCLUDED.value",
                    list((state or {}).items()),
                )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.executemany(
                    "INSERT OR REPLACE INTO threat_feed_vulnerabilities VALUES (?,?,?)", values
                )
                db.executemany(
                    "INSERT OR REPLACE INTO threat_feed_state VALUES (?,?)",
                    list((state or {}).items()),
                )
        else:
            self.memory_vulnerabilities.update(
                {item[0]: FeedVulnerability.model_validate_json(item[2]) for item in values}
            )
            self.memory_state.update(state or {})

    def prune_vulnerabilities(self, cutoff: datetime) -> None:
        if self.psycopg is not None:
            with self.psycopg.connect(self.url) as db:
                db.execute(
                    "DELETE FROM threat_feed_vulnerabilities WHERE activity_at < %s",
                    (cutoff.isoformat(),),
                )
        elif self.backend == "sqlite":
            with sqlite3.connect(self.path) as db:
                db.execute(
                    "DELETE FROM threat_feed_vulnerabilities WHERE activity_at < ?",
                    (cutoff.isoformat(),),
                )
        else:
            self.memory_vulnerabilities = {
                key: value
                for key, value in self.memory_vulnerabilities.items()
                if value.activity_at >= cutoff
            }
