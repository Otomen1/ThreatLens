"""Environment-driven configuration for the Collections storage backend.

Mirrors ``cases/config.py``'s ``from_env`` pattern exactly: a frozen
dataclass built from environment variables, with a sane offline default so
Collections works with zero configuration in local/self-hosted single-user
deployments. A separate env var and default directory from both Workspace's
``THREATLENS_WORKSPACE_DIR`` and Cases' ``THREATLENS_CASES_DIR`` — no two of
the three storage roots ever overlap.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_STORAGE_DIR = "data/collections"


@dataclass(frozen=True)
class CollectionSettings:
    """Resolved Collections configuration (immutable)."""

    storage_dir: Path = Path(_DEFAULT_STORAGE_DIR)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> CollectionSettings:
        """Build settings from environment variables (``os.environ`` by default)."""
        source: Mapping[str, str] = os.environ if env is None else env
        raw = source.get("THREATLENS_COLLECTIONS_DIR")
        storage_dir = Path(raw) if raw and raw.strip() else Path(_DEFAULT_STORAGE_DIR)
        return cls(storage_dir=storage_dir)
