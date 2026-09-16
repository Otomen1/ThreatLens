"""Twelve-hour investigation snapshot cache with free storage adapters."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel

from ..reasoning.engine import ENGINE_VERSION

DEFAULT_TTL_SECONDS = 12 * 60 * 60
_PROVIDER_SECRET_NAMES = (
    "ABUSEIPDB_API_KEY",
    "ABUSE_CH_AUTH_KEY",
    "CENSYS_PERSONAL_ACCESS_TOKEN",
    "MALWAREBAZAAR_AUTH_KEY",
    "OTX_API_KEY",
    "SHODAN_API_KEY",
    "VIRUSTOTAL_API_KEY",
)


@dataclass(frozen=True)
class CacheEntry:
    payload: dict[str, Any]
    cached_at: datetime
    expires_at: datetime


def cache_key(*, entity_type: str, value: str, scan_mode: str, providers: list[str]) -> str:
    configuration_material = "|".join(
        f"{name}:{os.getenv(name, '')}" for name in _PROVIDER_SECRET_NAMES
    )
    configuration_version = hashlib.sha256(configuration_material.encode()).hexdigest()[:16]
    material = json.dumps(
        {
            "entity_type": entity_type,
            "value": value,
            "scan_mode": scan_mode,
            "providers": sorted(providers),
            "provider_configuration": configuration_version,
            "engine": ENGINE_VERSION,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode()).hexdigest()


class InvestigationCache:
    """Small cache that chooses PostgreSQL, SQLite, or a local JSON file."""

    def __init__(self) -> None:
        self._backend = os.getenv("THREATLENS_STORAGE_BACKEND", "file").lower()
        self._url = os.getenv("DATABASE_URL", "")
        self._database = Path(os.getenv("THREATLENS_DATABASE_PATH", "data/threatlens.db"))
        self._file = Path(os.getenv("THREATLENS_CACHE_PATH", "/tmp/threatlens-cache.json"))
        self._psycopg: Any | None = None
        self._memory: dict[str, CacheEntry] = {}
        self._initialize()

    def _initialize(self) -> None:
        if self._backend == "postgres" and self._url:
            self._psycopg = cast(Any, importlib.import_module("psycopg"))
            with self._psycopg.connect(self._url) as connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS threatlens_investigation_cache (
                    cache_key text PRIMARY KEY, cached_at timestamptz NOT NULL,
                    expires_at timestamptz NOT NULL, payload jsonb NOT NULL)""")
        elif self._backend == "sqlite":
            self._database.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self._database) as connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS investigation_cache (
                    cache_key TEXT PRIMARY KEY, cached_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL, payload TEXT NOT NULL)""")

    def get(self, key: str) -> CacheEntry | None:
        entry = self._read(key)
        if entry is None or entry.expires_at <= datetime.now(UTC):
            if entry is not None:
                self.delete(key)
            return None
        return entry

    def set(self, key: str, value: BaseModel) -> CacheEntry:
        cached_at = datetime.now(UTC)
        entry = CacheEntry(
            payload=value.model_dump(mode="json"),
            cached_at=cached_at,
            expires_at=cached_at + timedelta(seconds=DEFAULT_TTL_SECONDS),
        )
        payload = json.dumps(entry.payload)
        if self._psycopg is not None:
            with self._psycopg.connect(self._url) as connection:
                connection.execute(
                    """INSERT INTO threatlens_investigation_cache
                    (cache_key, cached_at, expires_at, payload) VALUES (%s,%s,%s,%s::jsonb)
                    ON CONFLICT (cache_key) DO UPDATE SET cached_at=EXCLUDED.cached_at,
                    expires_at=EXCLUDED.expires_at,payload=EXCLUDED.payload""",
                    (key, entry.cached_at, entry.expires_at, payload),
                )
        elif self._backend == "sqlite":
            with sqlite3.connect(self._database) as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO investigation_cache VALUES (?,?,?,?)",
                    (key, entry.cached_at.isoformat(), entry.expires_at.isoformat(), payload),
                )
        else:
            self._memory[key] = entry
        return entry

    def _read(self, key: str) -> CacheEntry | None:
        if self._psycopg is not None:
            with self._psycopg.connect(self._url) as connection:
                row = connection.execute(
                    "SELECT payload,cached_at,expires_at "
                    "FROM threatlens_investigation_cache WHERE cache_key=%s",
                    (key,),
                ).fetchone()
            if row:
                return CacheEntry(payload=dict(row[0]), cached_at=row[1], expires_at=row[2])
        elif self._backend == "sqlite":
            with sqlite3.connect(self._database) as connection:
                row = connection.execute(
                    "SELECT payload,cached_at,expires_at "
                    "FROM investigation_cache WHERE cache_key=?",
                    (key,),
                ).fetchone()
            if row:
                return CacheEntry(
                    payload=json.loads(row[0]),
                    cached_at=datetime.fromisoformat(row[1]),
                    expires_at=datetime.fromisoformat(row[2]),
                )
        return self._memory.get(key)

    def delete(self, key: str) -> None:
        if self._psycopg is not None:
            with self._psycopg.connect(self._url) as connection:
                connection.execute(
                    "DELETE FROM threatlens_investigation_cache WHERE cache_key=%s", (key,)
                )
        elif self._backend == "sqlite":
            with sqlite3.connect(self._database) as connection:
                connection.execute("DELETE FROM investigation_cache WHERE cache_key=?", (key,))
        self._memory.pop(key, None)
