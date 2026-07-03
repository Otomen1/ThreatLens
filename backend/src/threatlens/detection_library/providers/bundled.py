"""A generic provider backed by a bundled/cached JSON corpus (Phase 4.6).

All seven Phase 4.6 sources share this one implementation: the per-repository
difference is *data* (a :class:`RuleSource` descriptor + a seed file), not code,
so a new repository plugs in without a framework change. A future provider that
fetches live from GitHub simply subclasses :class:`CommunityProvider` and
overrides ``iter_records`` — the normalize/index/search/match layers are
unchanged.

The records are read from the local cache when present (populated by ``sync``),
falling back to the bundled offline seed shipped in ``detection_library/seed/``.
Either way the library works fully offline.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from ..models import RuleSource
from .base import CommunityProvider

_SEED_DIR = Path(__file__).resolve().parent.parent / "seed"


class BundledCommunityProvider(CommunityProvider):
    """A community provider whose records come from a bundled JSON seed file."""

    def __init__(self, source: RuleSource, *, seed_dir: Path | None = None) -> None:
        self._source = source
        self._seed_dir = seed_dir or _SEED_DIR

    @property
    def metadata(self) -> RuleSource:
        return self._source

    def iter_records(self) -> Iterable[dict[str, object]]:
        path = self._seed_dir / f"{self._source.id}.json"
        if not path.exists():
            return ()
        loaded = json.loads(path.read_text(encoding="utf-8"))
        records = loaded.get("rules", loaded) if isinstance(loaded, dict) else loaded
        return tuple(records) if isinstance(records, list) else ()
