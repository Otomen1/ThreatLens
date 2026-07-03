"""Synchronization & offline cache for the Detection Knowledge Library (Phase 4.6).

Synchronization is deliberately **separate from investigation**. The flow is:

    repositories → synchronize() → local cache → indexed library → offline search

``synchronize`` is the only clock-aware, potentially-network-touching step, and it
is never called on the investigation path — an investigation reads an already
-built :class:`DetectionLibrary` (from the cache, or the bundled seed) and never
depends on GitHub. In this phase the shipped providers are bundled (offline), so
``synchronize`` snapshots the seed; a future live-fetch provider (a
``CommunityProvider`` subclass) plugs in here with no change to caching, indexing,
search, or matching.

Supports incremental updates (per-rule content-hash diffing), version tracking
(per-source aggregate hash), cache invalidation, and a fully offline read path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .library import DetectionLibrary
from .models import CommunityRule
from .providers.base import CommunityProviderRegistry
from .types import SyncStatus

CACHE_VERSION = "1.0"


class LibraryCache(BaseModel):
    """A serializable, offline snapshot of the synced library."""

    model_config = ConfigDict(frozen=True)

    cache_version: str = CACHE_VERSION
    synced_at: datetime | None = None
    rule_count: int = Field(default=0, ge=0)
    source_versions: dict[str, str] = Field(default_factory=dict)
    rules: tuple[CommunityRule, ...] = ()


@dataclass(frozen=True)
class SyncDiff:
    """The incremental delta between two caches (for version tracking)."""

    added: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.changed or self.removed)


def source_version(rules: tuple[CommunityRule, ...]) -> str:
    """A stable aggregate fingerprint over a set of rules (order-independent)."""
    digest = hashlib.sha256()
    for content_hash in sorted(rule.version.content_hash for rule in rules):
        digest.update(content_hash.encode("utf-8"))
    return digest.hexdigest()[:16]


def synchronize(
    registry: CommunityProviderRegistry, *, now: datetime | None = None
) -> LibraryCache:
    """Pull normalized rules from every provider into a cache snapshot.

    The one clock-aware step (records ``synced_at``); never called during an
    investigation. Offline providers snapshot their seed; a live provider would
    fetch here without changing anything downstream.
    """
    rules = registry.all_rules()
    versions: dict[str, str] = {}
    for provider in registry.providers:
        versions[provider.metadata.id] = source_version(provider.rules())
    return LibraryCache(
        synced_at=now,
        rule_count=len(rules),
        source_versions=versions,
        rules=rules,
    )


def diff(old: LibraryCache | None, new: LibraryCache) -> SyncDiff:
    """Per-rule incremental delta (added / content-changed / removed)."""
    old_map = {r.rule_id: r.version.content_hash for r in (old.rules if old else ())}
    new_map = {r.rule_id: r.version.content_hash for r in new.rules}
    added = tuple(sorted(k for k in new_map if k not in old_map))
    removed = tuple(sorted(k for k in old_map if k not in new_map))
    changed = tuple(sorted(k for k in new_map if k in old_map and new_map[k] != old_map[k]))
    return SyncDiff(added=added, changed=changed, removed=removed)


# --------------------------------------------------------------------------- #
# Cache I/O (best-effort; the library always works without it)
# --------------------------------------------------------------------------- #


def write_cache(cache: LibraryCache, path: Path) -> None:
    """Persist a cache snapshot atomically (creates parent dirs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(cache.model_dump_json(indent=2), encoding="utf-8")
    tmp.replace(path)


def read_cache(path: Path) -> LibraryCache | None:
    """Load a cache snapshot, or ``None`` if absent/unreadable/incompatible."""
    if not path.exists():
        return None
    try:
        cache = LibraryCache.model_validate_json(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return cache if cache.cache_version == CACHE_VERSION else None


def invalidate(path: Path) -> bool:
    """Delete the cache file so the next load falls back to seed/re-sync."""
    if path.exists():
        path.unlink()
        return True
    return False


def is_stale(cache: LibraryCache, *, now: datetime, ttl_seconds: int) -> bool:
    """True when a synced cache is older than its TTL (needs a refresh)."""
    if cache.synced_at is None:
        return False
    return (now - cache.synced_at).total_seconds() > ttl_seconds


def library_from_cache(cache: LibraryCache, *, stale: bool = False) -> DetectionLibrary:
    """Build an indexed library from a cache snapshot."""
    status = SyncStatus.STALE if stale else SyncStatus.SYNCED
    return DetectionLibrary(cache.rules, sync_status=status, version=CACHE_VERSION)
