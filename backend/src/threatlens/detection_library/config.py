"""Configuration for the Detection Knowledge Library (Phase 4.6).

Deliberately minimal. The library works fully offline from the bundled seed with
**no** configuration; a cache directory is optional and only used to hold content
synced from upstream. When no cache directory is configured (the default), the
service is stateless and reads only the bundled seed — ideal for ephemeral /
serverless deployments where the investigation must never touch the network.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # a synced cache older than this is "stale"


@dataclass(frozen=True)
class DetectionLibraryConfig:
    """Where (optionally) the synced cache lives and how long it stays fresh."""

    cache_dir: Path | None = None
    cache_ttl_seconds: int = _DEFAULT_TTL_SECONDS

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> DetectionLibraryConfig:
        """Build from ``THREATLENS_DKL_*`` variables (all optional)."""
        source = env if env is not None else dict(os.environ)
        raw_dir = source.get("THREATLENS_DKL_CACHE_DIR", "").strip()
        raw_ttl = source.get("THREATLENS_DKL_CACHE_TTL_SECONDS", "").strip()
        ttl = int(raw_ttl) if raw_ttl.isdigit() else _DEFAULT_TTL_SECONDS
        return cls(cache_dir=Path(raw_dir) if raw_dir else None, cache_ttl_seconds=ttl)

    @property
    def cache_path(self) -> Path | None:
        """The cache file path, or ``None`` when no cache directory is configured."""
        return self.cache_dir / "library_cache.json" if self.cache_dir else None
