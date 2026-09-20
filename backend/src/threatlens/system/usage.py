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
    BackupOperationUsage,
    DetectionEngineeringUsage,
    DetectionKnowledgeUsage,
    InvestigationUsage,
    KnowledgeProviderUsage,
    ProviderEvent,
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
        _provider_usage(item, metrics.ti_providers.get(item.name), metrics) for item in ti.providers
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
        generation_failures=sum(metrics.detection_generation_issues.values()),
        failures_by_generator=dict(metrics.detection_generation_issues),
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
        backups=[
            BackupOperationUsage(
                operation=name,
                requests=counter.requests,
                successful=counter.successes,
                failed=counter.failures,
                avg_latency_ms=counter.avg_latency_ms,
                last_request_at=counter.last_request_at,
            )
            for name, counter in sorted(metrics.backup_operations.items())
        ],
        timestamp=_now(),
        recent_provider_events=[
            ProviderEvent.model_validate(item) for item in metrics.provider_events[-50:]
        ],
    )


def _provider_usage(
    item: ProviderStatusItem, counter: CallCounter | None, metrics: MetricsRegistry
) -> ProviderUsage:
    c = counter or CallCounter()
    quota = metrics.provider_quota.get(item.name, {})
    recent = [event for event in metrics.provider_events if event["provider"] == item.name]
    # HTTP events are durable, unlike the process-local aggregate counters. On
    # serverless hosts the usage request may run in a different instance from
    # the investigation, so prefer the event ledger whenever it has data.
    # The ledger is intentionally bounded to the latest 500 events.
    requests = len(recent) if recent else c.requests
    successful = 0
    if recent:
        for event in recent:
            event_status = event.get("status_code")
            if (
                isinstance(event_status, int)
                and not isinstance(event_status, bool)
                and (event_status < 400 or event_status == 404)
            ):
                successful += 1
    else:
        successful = c.successes
    failed = requests - successful if recent else c.failures
    success_rate = round(100 * successful / requests, 1) if requests else None
    last_request_at = (
        str(recent[-1]["timestamp"])
        if recent and recent[-1].get("timestamp") is not None
        else c.last_request_at
    )
    status_value = recent[-1].get("status_code") if recent else None
    last_status = status_value if isinstance(status_value, int) else None
    error_code = (
        "rate_limited"
        if last_status == 429
        else "unauthorized"
        if last_status in {401, 403}
        else "upstream_error"
        if last_status is not None and last_status >= 500
        else None
    )
    actions = {
        "rate_limited": "Wait for the provider reset, then retry manually.",
        "unauthorized": "Check the provider API key in Vercel.",
        "upstream_error": "The provider is unavailable; retry later.",
    }
    action = actions.get(error_code) if error_code is not None else None
    remaining = quota.get("remaining")
    limit = quota.get("limit")
    reset = quota.get("reset_at")
    retry_after = quota.get("retry_after")
    return ProviderUsage(
        name=item.name,
        display_name=item.display_name,
        configured=item.configured,
        enabled=item.enabled,
        requests=requests,
        successful=successful,
        failed=failed,
        success_rate=success_rate,
        avg_latency_ms=c.avg_latency_ms,
        last_request_at=last_request_at,
        rate_limit_remaining=remaining if isinstance(remaining, int) else None,
        cache_hits=c.cache_hits,
        cache_misses=c.cache_misses,
        rate_limit=limit if isinstance(limit, int) else None,
        rate_limit_reset_at=reset if isinstance(reset, str) else None,
        retry_after=retry_after if isinstance(retry_after, str) else None,
        rate_limited_count=sum(1 for event in recent if event["rate_limited"]),
        last_safe_error_code=error_code,
        suggested_action=action,
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
