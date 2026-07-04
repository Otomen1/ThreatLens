"""Aggregated API-consumption usage for the dashboard (Section 2).

Combines the in-memory counters from :mod:`.metrics` with the existing,
already-tested configuration checks in ``api/health.py`` (so every provider
appears even before its first request) and the Detection Knowledge Library's
own read-only stats/cache accessors. Nothing here calls a provider, runs an
investigation, or scans historical data — every value is either an
incremental counter or a cheap, current-state read.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..ai.config import AISettings
from ..detection_library.config import DetectionLibraryConfig
from ..detection_library.service import DetectionKnowledgeService
from ..detection_library.sync import read_cache
from .metrics import CallCounter, MetricsRegistry
from .schemas import (
    AIUsage,
    DetectionEngineeringUsage,
    DetectionKnowledgeUsage,
    InvestigationUsage,
    KnowledgeProviderUsage,
    ProviderUsage,
    UsageResponse,
)

if TYPE_CHECKING:
    from ..api.health import KnowledgeDatasetItem, ProviderStatusItem


def _now() -> str:
    return datetime.now(UTC).isoformat()


async def build_usage(
    *,
    metrics: MetricsRegistry,
    knowledge_service: DetectionKnowledgeService,
) -> UsageResponse:
    from ..api.health import ai_health, knowledge_health, providers_health

    ti = providers_health()
    ti_usage = [
        _provider_usage(item, metrics.ti_providers.get(item.name)) for item in ti.providers
    ]

    kb = knowledge_health()
    kb_usage = [_knowledge_usage(item, metrics.kb_providers.get(item.name)) for item in kb.datasets]

    ai_settings = AISettings.from_env()
    ai_probe = await ai_health()
    ai_counter = metrics.ai
    ai_usage = AIUsage(
        provider=ai_settings.provider,
        model=ai_settings.ollama_model if ai_settings.enabled else None,
        enabled=ai_settings.enabled,
        connected=bool(ai_probe.reachable),
        requests=ai_counter.requests,
        successful=ai_counter.successes,
        failed=ai_counter.failures,
        avg_response_ms=ai_counter.avg_latency_ms,
        fastest_response_ms=ai_counter.latency_min_ms,
        slowest_response_ms=ai_counter.latency_max_ms,
        avg_prompt_chars=metrics.ai_prompt_chars.average,
        avg_completion_chars=metrics.ai_completion_chars.average,
    )

    detection_usage = DetectionEngineeringUsage(
        generated_total=sum(metrics.detection_by_language.values()),
        by_language=dict(metrics.detection_by_language),
        avg_generation_ms=metrics.detection_generation_ms.average,
        last_generated_at=metrics.detection_last_generated_at,
    )

    dkl_usage = _detection_knowledge_usage(knowledge_service, metrics)

    investigations = InvestigationUsage(
        executed=metrics.investigation_duration_ms.count,
        avg_duration_ms=metrics.investigation_duration_ms.average,
        avg_findings=metrics.investigation_findings.average,
        avg_recommendations=metrics.investigation_recommendations.average,
        avg_confidence=metrics.investigation_confidence.average,
        avg_ai_response_ms=ai_counter.avg_latency_ms,
    )

    return UsageResponse(
        threat_intelligence=ti_usage,
        knowledge=kb_usage,
        ai=ai_usage,
        detection_engineering=detection_usage,
        detection_knowledge=dkl_usage,
        investigations=investigations,
        timestamp=_now(),
    )


def _provider_usage(item: ProviderStatusItem, counter: CallCounter | None) -> ProviderUsage:
    c = counter or CallCounter()
    return ProviderUsage(
        name=item.name,
        display_name=item.display_name,
        configured=item.configured,
        enabled=item.enabled,
        requests=c.requests,
        successful=c.successes,
        failed=c.failures,
        success_rate=c.success_rate,
        avg_latency_ms=c.avg_latency_ms,
        last_request_at=c.last_request_at,
        rate_limit_remaining=None,  # not exposed by any provider today
        cache_hits=c.cache_hits,
        cache_misses=c.cache_misses,
    )


def _knowledge_usage(
    item: KnowledgeDatasetItem, counter: CallCounter | None
) -> KnowledgeProviderUsage:
    c = counter or CallCounter()
    return KnowledgeProviderUsage(
        name=item.name,
        display_name=item.display_name,
        queries=c.requests,
        successful=c.successes,
        failed=c.failures,
        avg_latency_ms=c.avg_latency_ms,
        cache_hits=c.cache_hits,
        cache_misses=c.cache_misses,
    )


def _detection_knowledge_usage(
    service: DetectionKnowledgeService, metrics: MetricsRegistry
) -> DetectionKnowledgeUsage:
    stats = service.stats()
    synced_at, cache_size = _read_cache_metadata()
    return DetectionKnowledgeUsage(
        library_version=stats.library_version,
        rules_indexed=stats.total_rules,
        repositories=stats.sources,
        sync_status=str(stats.sync_status),
        last_synchronized_at=synced_at,
        cache_size_bytes=cache_size,
        queries=metrics.dkl_queries.requests,
        avg_query_latency_ms=metrics.dkl_queries.avg_latency_ms,
    )


def _read_cache_metadata() -> tuple[str | None, int | None]:
    """Best-effort read of the synced-cache file's timestamp and size.

    Returns ``(None, None)`` when no cache directory is configured (the
    default, bundled-seed-only mode) or the cache file does not exist yet —
    both are normal, expected states, not errors.
    """
    config = DetectionLibraryConfig.from_env()
    cache_path = config.cache_path
    if cache_path is None or not cache_path.exists():
        return None, None
    cache = read_cache(cache_path)
    synced_at = cache.synced_at.isoformat() if cache and cache.synced_at else None
    try:
        size = Path(cache_path).stat().st_size
    except OSError:
        size = None
    return synced_at, size
