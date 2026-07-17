"""Tests for Intelligence Collections' LocalFileStorage (Phase 9.1).

Mirrors ``tests/cases/test_storage.py`` exactly. Every test uses pytest's
``tmp_path`` fixture — no test ever touches the developer's real filesystem
or the default ``data/collections`` directory, and every test is fully
offline.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from threatlens.collections import CollectionNotFoundError, CollectionStorageError, LocalFileStorage

from .factories import collection


class TestLocalFileStorage:
    def test_creates_root_directory(self, tmp_path: Path) -> None:
        root = tmp_path / "nested" / "collections"
        assert not root.exists()
        LocalFileStorage(root)
        assert root.exists()

    def test_unwritable_root_raises_storage_error(self, tmp_path: Path) -> None:
        """A root whose parent path component is a file (not a directory) can
        never be created — a portable, unmocked stand-in for a read-only or
        misconfigured deployment filesystem, mirroring the same Vercel-safety
        guard Workspace and Case storage already have."""
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        with pytest.raises(CollectionStorageError):
            LocalFileStorage(blocker / "collections")

    def test_save_then_load_round_trips(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        record = collection(name="Round trip")
        storage.save(record)
        assert storage.load(record.id) == record

    def test_save_writes_one_json_file_per_record(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        record = collection()
        storage.save(record)
        assert (tmp_path / f"{record.id}.json").exists()

    def test_save_leaves_no_temp_file_behind(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        storage.save(collection())
        assert list(tmp_path.glob("*.tmp")) == []

    def test_overwrite_replaces_content(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        record = collection(name="Original")
        storage.save(record)
        updated = record.model_copy(update={"name": "Renamed"})
        storage.save(updated)
        assert storage.load(record.id).name == "Renamed"

    def test_load_missing_raises_not_found(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        with pytest.raises(CollectionNotFoundError):
            storage.load(uuid4())

    def test_delete_missing_raises_not_found(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        with pytest.raises(CollectionNotFoundError):
            storage.delete(uuid4())

    def test_delete_removes_file(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        record = collection()
        storage.save(record)
        storage.delete(record.id)
        assert not (tmp_path / f"{record.id}.json").exists()
        with pytest.raises(CollectionNotFoundError):
            storage.load(record.id)

    def test_exists_true_after_save_false_after_delete(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        record = collection()
        assert storage.exists(record.id) is False
        storage.save(record)
        assert storage.exists(record.id) is True
        storage.delete(record.id)
        assert storage.exists(record.id) is False

    def test_list_all_empty_directory(self, tmp_path: Path) -> None:
        assert LocalFileStorage(tmp_path).list_all() == []

    def test_list_all_returns_every_saved_record(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        records = [collection(name=f"Collection {i}") for i in range(5)]
        for record in records:
            storage.save(record)
        listed = storage.list_all()
        assert {r.id for r in listed} == {r.id for r in records}

    def test_list_all_skips_corrupt_files(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        good = collection(name="Good")
        storage.save(good)
        (tmp_path / "corrupt.json").write_text("{not valid json")
        listed = storage.list_all()
        assert len(listed) == 1
        assert listed[0].id == good.id

    def test_load_corrupt_file_raises_storage_error(self, tmp_path: Path) -> None:
        storage = LocalFileStorage(tmp_path)
        bad_id = uuid4()
        (tmp_path / f"{bad_id}.json").write_text("{not valid json")
        with pytest.raises(CollectionStorageError):
            storage.load(bad_id)

    def test_second_instance_over_same_root_sees_prior_data(self, tmp_path: Path) -> None:
        """Persistence survives process restarts — the whole point of
        local-file storage."""
        record = collection(name="Survives restart")
        LocalFileStorage(tmp_path).save(record)
        reloaded = LocalFileStorage(tmp_path).load(record.id)
        assert reloaded == record
