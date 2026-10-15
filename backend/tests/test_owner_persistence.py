"""Synthetic-data concurrency, cache persistence and backup ownership regressions."""

import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from multiprocessing import get_context
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel

from threatlens.api.routes.backup import BackupBundle, _digest, _errors, restore_backup
from threatlens.cases import Case, CaseService
from threatlens.cases.sqlite_storage import SQLiteCaseStorage
from threatlens.investigation.cache import InvestigationCache
from threatlens.record_database import postgres_transaction, sqlite_transaction
from threatlens.workspace import LocalFileStorage, WorkspaceInvestigation, WorkspaceService
from threatlens.workspace.sqlite_storage import SQLiteWorkspaceStorage

OWNER = "00000000-0000-4000-8000-000000000001"


def record():
    now = datetime.now(UTC)
    return WorkspaceInvestigation(
        id=uuid4(), title="Synthetic", created_at=now, updated_at=now, investigation_type="domain"
    )


def test_unique_file_writes_nested_locks_and_cleanup(tmp_path):
    storage = LocalFileStorage(tmp_path / "records")
    value = record()
    with storage.lock():
        storage.save(value)
    with ThreadPoolExecutor(max_workers=6) as workers:
        list(
            workers.map(
                lambda i: storage.save(value.model_copy(update={"title": str(i)})), range(30)
            )
        )
    assert storage.load(value.id).title in {str(i) for i in range(30)}
    assert not list((tmp_path / "records").glob("*.tmp"))


def _increment_file_record(root: str, identifier: str) -> None:
    storage = LocalFileStorage(Path(root))
    for _ in range(5):
        with storage.lock():
            current = storage.load(UUID(identifier))
            storage.save(current.model_copy(update={"title": str(int(current.title) + 1)}))


def test_local_transactions_serialize_across_processes(tmp_path):
    storage = LocalFileStorage(tmp_path / "records")
    value = record().model_copy(update={"title": "0"})
    storage.save(value)
    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as workers:
        futures = [
            workers.submit(_increment_file_record, str(tmp_path / "records"), str(value.id))
            for _ in range(4)
        ]
        for future in futures:
            future.result(timeout=20)
    assert storage.load(value.id).title == "20"


def test_sqlite_adapters_are_thread_safe_and_share_rollback(tmp_path):
    path = tmp_path / "records.db"
    workspace, cases = SQLiteWorkspaceStorage(path), SQLiteCaseStorage(path)
    values = [record() for _ in range(12)]
    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(workspace.save, values))
    assert len(workspace.list_all()) == 12
    new = record()
    case = Case(id=uuid4(), title="Synthetic", created_at=new.created_at, updated_at=new.updated_at)
    with pytest.raises(RuntimeError), sqlite_transaction(path):
        workspace.save(new)
        cases.save(case)
        raise RuntimeError("Synthetic failure")
    assert not workspace.exists(new.id) and not cases.exists(case.id)


@pytest.mark.parametrize("backend", ["file", "sqlite"])
def test_cache_reopens_expires_and_keeps_concurrent_entries(tmp_path, monkeypatch, backend):
    class Sample(BaseModel):
        value: str

    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", backend)
    monkeypatch.setenv("THREATLENS_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "cache.db"))

    def write(i):
        return InvestigationCache().set(str(i), Sample(value=str(i)))

    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(write, range(12)))
    reopened = InvestigationCache()
    assert all(reopened.get(str(i)) is not None for i in range(12))
    reopened.delete("0")
    assert InvestigationCache().get("0") is None
    if backend == "file":
        path = tmp_path / "cache.json"
        payload = json.loads(path.read_text())
        payload["1"]["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        path.write_text(json.dumps(payload))
        assert reopened.get("1") is None


def test_postgres_transaction_reuses_connection_and_lock():
    statements, connections = [], []

    class Connection:
        def execute(self, *args):
            statements.append(args)

    class Driver:
        @staticmethod
        @contextmanager
        def connect(url):
            db = Connection()
            connections.append(db)
            yield db

    with (
        postgres_transaction(Driver, "mock-url") as first,
        postgres_transaction(Driver, "mock-url") as second,
    ):
        assert first is second
    assert len(connections) == 1 and "pg_advisory_xact_lock" in statements[0][0]


def test_backup_owner_and_legacy_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    path = tmp_path / "records.db"
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(path))
    workspace = WorkspaceService(SQLiteWorkspaceStorage(path))
    cases = CaseService(SQLiteCaseStorage(path), workspace)
    bundle = BackupBundle(
        exported_at=datetime.now(UTC), owner_user_id=OWNER, investigations=[record()]
    )
    bundle = bundle.model_copy(update={"digest": _digest(bundle)})
    assert not _errors(bundle)
    assert restore_backup(bundle, workspace, cases).investigations_added == 1
    assert restore_backup(bundle, workspace, cases).investigations_skipped == 1
    wrong = bundle.model_copy(update={"owner_user_id": str(uuid4())})
    assert "Backup ownership does not match this personal workspace." in _errors(wrong)
    legacy = bundle.model_copy(update={"schema_version": 1, "owner_user_id": None})
    legacy = legacy.model_copy(update={"digest": _digest(legacy)})
    with pytest.raises(Exception, match="Confirm ownership"):
        restore_backup(legacy, workspace, cases)
    assert restore_backup(legacy, workspace, cases, allow_legacy=True).investigations_skipped == 1


def test_sqlite_restore_rolls_back_both_record_families(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "sqlite")
    path = tmp_path / "rollback.db"
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(path))
    workspace = WorkspaceService(SQLiteWorkspaceStorage(path))
    cases = CaseService(SQLiteCaseStorage(path), workspace)
    value = record()
    bundle = BackupBundle(
        exported_at=datetime.now(UTC), owner_user_id=OWNER, investigations=[value]
    )
    bundle = bundle.model_copy(update={"digest": _digest(bundle)})

    def failed(_records):
        raise RuntimeError("Synthetic second-family failure")

    monkeypatch.setattr(cases, "merge_snapshot", failed)
    with pytest.raises(RuntimeError, match="second-family"):
        restore_backup(bundle, workspace, cases)
    assert workspace.snapshot() == []
