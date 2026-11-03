"""Cold initialization, read-only reloads and bounded database waits."""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.api.routes import threat_feed as routes
from threatlens.ioc_feed.storage import IocStorage
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage


def test_concurrent_sqlite_cold_starts_and_current_schema_skip(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "feed.db"))
    original = FeedStorage._schema
    calls = []

    def setup(db, *, postgres):
        calls.append(1)
        time.sleep(0.02)
        original(db, postgres=postgres)

    monkeypatch.setattr(FeedStorage, "_schema", staticmethod(setup))

    def create(_):
        store = FeedStorage()
        IocStorage(store)
        return store

    with ThreadPoolExecutor(max_workers=6) as pool:
        stores = list(pool.map(create, range(6)))
    assert len(calls) == 1
    assert all(s.state("schema:feed_v1") == "ready" for s in stores)
    assert FeedStorage().state("schema:ioc_v1") == "ready"


def test_sqlite_failed_setup_rolls_back_marker_and_ddl(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "feed.db"))
    store = FeedStorage()

    def broken(db):
        db.execute("CREATE TABLE regression_example(id text)")
        raise RuntimeError("failed setup")

    with pytest.raises(RuntimeError):
        store.ensure_schema("broken_v1", broken)
    assert store.state("schema:broken_v1") is None
    with sqlite3.connect(store.path) as db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='regression_example'"
        ).fetchone()


def test_postgres_schema_lock_precedes_ddl_and_rechecks_marker(monkeypatch):
    """Driver protocol fixture; live PostgreSQL rollout remains a separate check."""
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    lock, state, events = threading.Lock(), {}, []

    class Connection:
        locked = False
        read_before_lock = False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            if self.locked:
                lock.release()

        def execute(self, sql, args=()):
            row = None
            if "pg_advisory_xact_lock" in sql:
                assert not self.read_before_lock, "Do not retain marker table locks while waiting"
                lock.acquire()
                self.locked = True
                events.append("lock")
            elif "to_regclass" in sql:
                row = ("threat_feed_state",)
            elif sql.startswith("SELECT value"):
                if not self.locked:
                    self.read_before_lock = True
                row = (state[args[0]],) if args[0] in state else None
            elif sql.startswith("INSERT INTO threat_feed_state"):
                state[args[0]] = "ready"
            return SimpleNamespace(fetchone=lambda: row)

    def create(_):
        store = FeedStorage()
        store.psycopg = SimpleNamespace(connect=lambda *_a, **_k: Connection())

        def setup(db):
            assert db.locked
            events.append("ddl")
            time.sleep(0.02)

        store.ensure_schema("test_v1", setup)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(create, range(6)))
    assert events.count("ddl") == 1 and events.index("lock") < events.index("ddl")


def test_feed_singleton_constructed_once_under_competing_requests(monkeypatch):
    monkeypatch.setattr(routes, "_service", None)
    storage, service = MagicMock(), MagicMock()
    monkeypatch.setattr(routes, "FeedStorage", storage)
    monkeypatch.setattr(routes, "ThreatFeedService", service)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: routes.get_threat_feed_service(), range(8)))
    assert all(result is results[0] for result in results)
    storage.assert_called_once()


def test_reload_bypasses_warm_cache_and_never_collects(monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    service = ThreatFeedService(FeedStorage())
    collect = MagicMock(side_effect=AssertionError("A read must not collect"))
    monkeypatch.setattr(service, "refresh", collect)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_threat_feed_service] = lambda: service
    with TestClient(app) as client:
        for path in ("home", "vulnerabilities"):
            first = client.get(f"/api/v1/threat-feed/{path}")
            fresh = client.get(
                f"/api/v1/threat-feed/{path}?fresh=true",
                headers={"If-None-Match": first.headers.get("etag", "")},
            )
            assert fresh.status_code == 200
            assert fresh.headers["cache-control"] == "no-store"
            assert "feed;dur=" in fresh.headers["server-timing"]
            assert fresh.json()["generated_at"] != first.json()["generated_at"]
            again = client.get(f"/api/v1/threat-feed/{path}")
            assert again.json()["generated_at"] == fresh.json()["generated_at"]
    collect.assert_not_called()


def test_home_etag_tracks_payload_changes_without_a_new_collection_timestamp(monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "memory")
    service = ThreatFeedService(FeedStorage())
    current = service.home()
    monkeypatch.setattr(service, "home", lambda **kwargs: current)
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.get_threat_feed_service] = lambda: service
    with TestClient(app) as client:
        first = client.get("/api/v1/threat-feed/home")
        current = current.model_copy(
            update={"summary": current.summary.model_copy(update={"new_iocs": 1})}
        )
        changed = client.get(
            "/api/v1/threat-feed/home", headers={"If-None-Match": first.headers["etag"]}
        )
        assert changed.status_code == 200 and changed.headers["etag"] != first.headers["etag"]
        unchanged = client.get(
            "/api/v1/threat-feed/home", headers={"If-None-Match": changed.headers["etag"]}
        )
        assert unchanged.status_code == 304
