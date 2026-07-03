"""Synchronization + offline cache tests (incremental, versioned, offline)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from threatlens.detection_library import (
    DetectionKnowledgeService,
    DetectionLibraryConfig,
    build_default_provider_registry,
    synchronize,
)
from threatlens.detection_library.sync import (
    diff,
    invalidate,
    is_stale,
    library_from_cache,
    read_cache,
    source_version,
    write_cache,
)
from threatlens.detection_library.types import SyncStatus

_NOW = datetime(2024, 6, 1, tzinfo=UTC)


def _registry():
    return build_default_provider_registry()


def test_synchronize_snapshots_every_rule() -> None:
    cache = synchronize(_registry(), now=_NOW)
    assert cache.rule_count == 18
    assert cache.synced_at == _NOW
    assert len(cache.source_versions) == 7


def test_cache_write_read_roundtrip(tmp_path: Path) -> None:
    cache = synchronize(_registry(), now=_NOW)
    path = tmp_path / "library_cache.json"
    write_cache(cache, path)
    loaded = read_cache(path)
    assert loaded == cache


def test_read_cache_absent_or_corrupt_returns_none(tmp_path: Path) -> None:
    assert read_cache(tmp_path / "missing.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert read_cache(bad) is None


def test_invalidate_deletes_cache(tmp_path: Path) -> None:
    path = tmp_path / "library_cache.json"
    write_cache(synchronize(_registry(), now=_NOW), path)
    assert invalidate(path) is True
    assert not path.exists()
    assert invalidate(path) is False  # already gone


def test_diff_detects_added_changed_removed() -> None:
    old = synchronize(_registry(), now=_NOW)
    # Simulate an upstream change: drop one rule and mutate another's hash.
    kept = list(old.rules[1:])
    mutated = kept[0].model_copy(
        update={"version": kept[0].version.model_copy(update={"content_hash": "deadbeef" * 8})}
    )
    new = old.model_copy(update={"rules": (mutated, *kept[1:])})
    delta = diff(old, new)
    assert old.rules[0].rule_id in delta.removed
    assert mutated.rule_id in delta.changed
    assert not delta.is_empty


def test_diff_empty_when_unchanged() -> None:
    cache = synchronize(_registry(), now=_NOW)
    assert diff(cache, cache).is_empty


def test_source_version_is_order_independent() -> None:
    rules = _registry().all_rules()
    assert source_version(rules) == source_version(tuple(reversed(rules)))


def test_is_stale_respects_ttl() -> None:
    cache = synchronize(_registry(), now=_NOW)
    later = _NOW + timedelta(days=10)
    assert is_stale(cache, now=later, ttl_seconds=3600) is True
    assert is_stale(cache, now=_NOW, ttl_seconds=3600) is False


def test_library_from_cache_marks_status() -> None:
    cache = synchronize(_registry(), now=_NOW)
    assert library_from_cache(cache).sync_status is SyncStatus.SYNCED
    assert library_from_cache(cache, stale=True).sync_status is SyncStatus.STALE


def test_service_prefers_cache_then_falls_back_to_seed(tmp_path: Path) -> None:
    # No cache configured → offline seed.
    seed_service = DetectionKnowledgeService.from_default(config=DetectionLibraryConfig())
    assert seed_service.stats().sync_status is SyncStatus.SEED

    # Cache present → served from cache.
    cfg = DetectionLibraryConfig(cache_dir=tmp_path)
    write_cache(synchronize(_registry(), now=_NOW), cfg.cache_path)  # type: ignore[arg-type]
    cached_service = DetectionKnowledgeService.from_default(config=cfg)
    assert cached_service.stats().sync_status is SyncStatus.SYNCED
    assert cached_service.stats().total_rules == 18


def test_investigation_path_never_needs_the_network() -> None:
    # The service is built once; recommend/search touch only the in-memory library.
    service = DetectionKnowledgeService.from_default(config=DetectionLibraryConfig())
    assert service.search(technique="T1071").total == 7
