"""Response models for the Operational Dashboard (Sections 1-3).

Every model here is operational metadata only: names, counts, timings,
booleans, and short status strings. None carries a secret, an API key, a
bearer token, a raw exception, or a stack trace — see
``docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md`` for the security
contract this module upholds.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class ServiceState(StrEnum):
    """The four states any monitored service can be in."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    DISABLED = "disabled"


class ServiceStatus(BaseModel):
    """Health of one named service or subsystem."""

    name: str
    display_name: str
    status: ServiceState
    detail: str


class SystemHealthResponse(BaseModel):
    """Section 1 — System Health: one row per service plus an overall rollup."""

    status: ServiceState
    services: list[ServiceStatus]
    timestamp: str


class ProviderUsage(BaseModel):
    """Runtime usage for one threat-intelligence provider."""

    name: str
    display_name: str
    configured: bool
    enabled: bool
    requests: int
    successful: int
    failed: int
    success_rate: float | None
    avg_latency_ms: float | None
    last_request_at: str | None
    rate_limit_remaining: int | None
    cache_hits: int
    cache_misses: int


class KnowledgeProviderUsage(BaseModel):
    """Runtime usage for one reference/knowledge provider."""

    name: str
    display_name: str
    queries: int
    successful: int
    failed: int
    avg_latency_ms: float | None
    cache_hits: int
    cache_misses: int


class AIUsage(BaseModel):
    """Runtime usage for the AI explanation layer."""

    provider: str
    model: str | None
    enabled: bool
    connected: bool
    requests: int
    successful: int
    failed: int
    avg_response_ms: float | None
    fastest_response_ms: float | None
    slowest_response_ms: float | None
    avg_prompt_chars: float | None
    avg_completion_chars: float | None
    # Reserved for a future remote (paid-token) provider; always null for
    # Ollama, which is local and free — never estimate a cost for it.
    estimated_tokens: float | None = None
    estimated_cost_usd: float | None = None


class DetectionEngineeringUsage(BaseModel):
    """Runtime usage for the Detection Engine (generation only, read-only)."""

    generated_total: int
    by_language: dict[str, int]
    avg_generation_ms: float | None
    last_generated_at: str | None


class DetectionKnowledgeUsage(BaseModel):
    """Current state + query usage for the Detection Knowledge Library."""

    library_version: str
    rules_indexed: int
    repositories: int
    sync_status: str
    last_synchronized_at: str | None
    cache_size_bytes: int | None
    queries: int
    avg_query_latency_ms: float | None


class InvestigationUsage(BaseModel):
    """Aggregate statistics across all investigations run this process."""

    executed: int
    avg_duration_ms: float | None
    avg_findings: float | None
    avg_recommendations: float | None
    avg_confidence: float | None
    avg_ai_response_ms: float | None


class UsageResponse(BaseModel):
    """Section 2 — API Consumption."""

    threat_intelligence: list[ProviderUsage]
    knowledge: list[KnowledgeProviderUsage]
    ai: AIUsage
    detection_engineering: DetectionEngineeringUsage
    detection_knowledge: DetectionKnowledgeUsage
    investigations: InvestigationUsage
    timestamp: str


class ConfigItem(BaseModel):
    """Configuration status for one provider — never the credential itself."""

    name: str
    display_name: str
    configured: bool
    enabled: bool


class AIConfigStatus(BaseModel):
    provider: str
    enabled: bool
    model: str | None


class ConfigStatusResponse(BaseModel):
    """Section 3 — Configuration Status."""

    threat_intelligence: list[ConfigItem]
    knowledge: list[ConfigItem]
    ai: AIConfigStatus
    timestamp: str
