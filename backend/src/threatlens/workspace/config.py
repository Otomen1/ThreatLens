"""Environment-driven configuration for the Investigation Workspace storage backend.

Mirrors ``ai/config.py``'s ``from_env`` pattern: a frozen dataclass built from
environment variables, with a sane offline default so the workspace works with
zero configuration in local/self-hosted single-user deployments.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_STORAGE_DIR = "data/workspace"


@dataclass(frozen=True)
class WorkspaceSettings:
    """Resolved Workspace configuration (immutable)."""

    storage_dir: Path = Path(_DEFAULT_STORAGE_DIR)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> WorkspaceSettings:
        """Build settings from environment variables (``os.environ`` by default)."""
        source: Mapping[str, str] = os.environ if env is None else env
        raw = source.get("THREATLENS_WORKSPACE_DIR")
        storage_dir = Path(raw) if raw and raw.strip() else Path(_DEFAULT_STORAGE_DIR)
        return cls(storage_dir=storage_dir)
