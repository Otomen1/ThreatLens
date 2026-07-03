"""The Detection Knowledge Library service facade (Phase 4.6).

A thin, offline-first wrapper the API depends on: it builds an indexed
:class:`DetectionLibrary` once (from the synced cache when configured & present,
otherwise the bundled seed) and exposes deterministic ``search`` and
``recommend``. Building the library is the only place cache I/O happens; every
query afterwards is pure and offline, so an investigation never reaches the
network.
"""

from __future__ import annotations

from datetime import datetime

from ..reasoning import InvestigationSummary
from .config import DetectionLibraryConfig
from .defaults import build_default_provider_registry
from .library import DetectionLibrary
from .matching import DEFAULT_LIMIT, recommend
from .models import CommunityRecommendation, CommunitySearchResult, LibraryStats
from .providers.base import CommunityProviderRegistry
from .sync import is_stale, library_from_cache, read_cache
from .types import DetectionLanguage, DetectionSeverity, RulePlatform, SyncStatus


class DetectionKnowledgeService:
    """Serves search + recommendations over an immutable indexed library."""

    def __init__(self, library: DetectionLibrary) -> None:
        self._library = library

    @classmethod
    def from_default(
        cls,
        *,
        config: DetectionLibraryConfig | None = None,
        registry: CommunityProviderRegistry | None = None,
        now: datetime | None = None,
    ) -> DetectionKnowledgeService:
        """Build the service, preferring a synced cache, falling back to seed."""
        cfg = config or DetectionLibraryConfig.from_env()
        reg = registry or build_default_provider_registry()

        cache_path = cfg.cache_path
        if cache_path is not None:
            cache = read_cache(cache_path)
            if cache is not None:
                stale = now is not None and is_stale(
                    cache, now=now, ttl_seconds=cfg.cache_ttl_seconds
                )
                return cls(library_from_cache(cache, stale=stale))

        # Offline default: the bundled seed corpus.
        seed = DetectionLibrary(reg.all_rules(), sync_status=SyncStatus.SEED)
        return cls(seed)

    @property
    def library(self) -> DetectionLibrary:
        return self._library

    def stats(self) -> LibraryStats:
        return self._library.stats()

    def recommend(
        self, summary: InvestigationSummary, *, limit: int = DEFAULT_LIMIT
    ) -> CommunityRecommendation:
        """Deterministic community recommendations for one investigation."""
        return recommend(summary, self._library, limit=limit)

    def search(
        self,
        *,
        ioc: str | None = None,
        technique: str | None = None,
        actor: str | None = None,
        malware: str | None = None,
        name: str | None = None,
        tag: str | None = None,
        rule_id: str | None = None,
        language: DetectionLanguage | None = None,
        repository: str | None = None,
        min_severity: DetectionSeverity | None = None,
        platform: RulePlatform | None = None,
        text: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> CommunitySearchResult:
        """Search the library by any combination of axes (AND-combined)."""
        return self._library.search(
            ioc=ioc,
            technique=technique,
            actor=actor,
            malware=malware,
            name=name,
            tag=tag,
            rule_id=rule_id,
            language=language,
            repository=repository,
            min_severity=min_severity,
            platform=platform,
            text=text,
            limit=limit,
            offset=offset,
        )
