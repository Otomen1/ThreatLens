"""Environment-driven configuration for the Investigation Workspace storage backend.

Mirrors ``ai/config.py``'s ``from_env`` pattern: a frozen dataclass built from
environment variables. File storage remains the zero-configuration default;
SQLite is enabled explicitly for durable deployments.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_STORAGE_DIR = "data/workspace"
_DEFAULT_DATABASE = "data/threatlens.db"


@dataclass(frozen=True)
class WorkspaceSettings:
    """Resolved Workspace configuration (immutable)."""

    storage_dir: Path = Path(_DEFAULT_STORAGE_DIR)
    storage_backend: str = "file"
    database_path: Path = Path(_DEFAULT_DATABASE)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> WorkspaceSettings:
        """Build settings from environment variables (``os.environ`` by default)."""
        source: Mapping[str, str] = os.environ if env is None else env
        raw = source.get("THREATLENS_WORKSPACE_DIR")
        storage_dir = Path(raw) if raw and raw.strip() else Path(_DEFAULT_STORAGE_DIR)
        backend = source.get("THREATLENS_STORAGE_BACKEND", "file").strip().lower()
        database = source.get("THREATLENS_DATABASE_PATH", _DEFAULT_DATABASE)
        return cls(storage_dir=storage_dir, storage_backend=backend, database_path=Path(database))
