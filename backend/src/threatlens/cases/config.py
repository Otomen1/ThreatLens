"""Environment-driven configuration for the Case Management storage backend.

Mirrors ``workspace/config.py``'s ``from_env`` pattern exactly: a frozen
dataclass built from environment variables, with a sane offline default so
Case Management works with zero configuration in local/self-hosted
single-user deployments. SQLite can be enabled explicitly to share a durable
database with Workspace while keeping the two domain tables separate.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_STORAGE_DIR = "data/cases"
_DEFAULT_DATABASE = "data/threatlens.db"


@dataclass(frozen=True)
class CaseSettings:
    """Resolved Case Management configuration (immutable)."""

    storage_dir: Path = Path(_DEFAULT_STORAGE_DIR)
    storage_backend: str = "file"
    database_path: Path = Path(_DEFAULT_DATABASE)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> CaseSettings:
        """Build settings from environment variables (``os.environ`` by default)."""
        source: Mapping[str, str] = os.environ if env is None else env
        raw = source.get("THREATLENS_CASES_DIR")
        storage_dir = Path(raw) if raw and raw.strip() else Path(_DEFAULT_STORAGE_DIR)
        backend = source.get("THREATLENS_STORAGE_BACKEND", "file").strip().lower()
        database = source.get("THREATLENS_DATABASE_PATH", _DEFAULT_DATABASE)
        return cls(storage_dir=storage_dir, storage_backend=backend, database_path=Path(database))
