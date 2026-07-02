"""Operational-readiness & health monitoring endpoints (Phase 3.17).

Production-grade, **read-only** observability for ThreatLens. These endpoints let
operators (and orchestrators like Kubernetes) answer three questions without
running an investigation or consuming any third-party API quota:

* Is the process alive?                      -> ``GET /health``
* Can it serve the deterministic core?       -> ``GET /ready``   (200 / 503)
* Are the subsystems configured & healthy?   -> ``GET /health/{providers,knowledge,ai}``
* What is running?                            -> ``GET /version``

**Guarantees.** Every check is side-effect-free and never mutates application
state. Threat-intelligence providers are *never* contacted (their configuration
is inferred from the environment, not from a live call), so health checks consume
no API quota. The single exception is ``GET /health/ai``, which — only when AI is
enabled — performs one lightweight Ollama reachability probe (``GET /api/tags``),
never a model generation. Nothing here touches the frozen Reasoning Engine, the
detection engine, the investigation pipeline, or the AI reasoning code; it only
*reports* on them.

The router is mounted twice by the app: at the root (``/health`` — for infra
probes hitting the backend directly) and under ``/api/v1`` (so a same-origin
frontend can reach it through the existing API base).
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from .. import __version__ as PLATFORM_VERSION
from ..ai.config import AISettings
from ..providers import HttpClient, ProviderHttpError
from ..providers._auth import abuse_ch_auth_key
from ..providers.defaults import build_default_registry
from ..reasoning import ENGINE_VERSION
from ..reference.defaults import build_default_reference_registry

API_VERSION = "v1"

# A reachability probe must fail fast — an unreachable model should never make a
# health check hang. This is independent of the (longer) generation timeout.
_AI_PROBE_TIMEOUT = 3.0

# Providers resolve credentials from these environment variables (mirroring each
# provider's own contract). Health infers "configured" from the environment so it
# never has to call a provider — the abuse.ch resolver is reused directly, and
# the two single-key providers are mapped explicitly. Kept beside the providers
# it monitors; a provider requiring auth with no key present is "unconfigured".
_ABUSE_CH_PROVIDERS = frozenset({"malwarebazaar", "urlhaus"})
_DIRECT_KEY_ENV = {"abuseipdb": "ABUSEIPDB_API_KEY", "otx": "OTX_API_KEY"}

# Build provenance is read from the environment (set by CI/deploy); absent in
# local/dev, where it reports ``null`` rather than shelling out to git.
_BUILD_COMMIT_ENVS = (
    "THREATLENS_BUILD_COMMIT",
    "VERCEL_GIT_COMMIT_SHA",
    "GIT_COMMIT",
    "SOURCE_COMMIT",
)
_BUILD_TIME_ENVS = ("THREATLENS_BUILD_TIME", "BUILD_TIMESTAMP")

# Built once at import: the deterministic core (detection, reasoning, bundled
# knowledge datasets) is fully offline, so constructing these has no network cost
# and the bundled datasets load exactly once. Per-request checks then only read
# already-resolved metadata — keeping every endpoint side-effect-free.
_TI_REGISTRY = build_default_registry()
_REF_REGISTRY = build_default_reference_registry()
_STARTED_MONO = time.monotonic()
_STARTED_AT = datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Response models (typed for OpenAPI; every field is derived, never mutated)
# --------------------------------------------------------------------------- #


class HealthStatus(BaseModel):
    """Liveness: the process is up and serving requests."""

    status: str = "ok"
    service: str = "threatlens"
    version: str
    uptime_seconds: float
    started_at: str
    timestamp: str


class ReadinessCheck(BaseModel):
    """One named readiness dependency."""

    name: str
    ready: bool
    detail: str


class Readiness(BaseModel):
    """Readiness: the deterministic core can serve investigations."""

    ready: bool
    checks: list[ReadinessCheck]
    timestamp: str


class ProviderStatusItem(BaseModel):
    """Configuration status for a single threat-intelligence provider."""

    name: str
    display_name: str
    enabled: bool
    requires_auth: bool
    configured: bool
    entity_types: list[str]


class ProvidersHealth(BaseModel):
    """Threat-intelligence provider configuration (no network calls)."""

    status: str
    configured: int
    total: int
    providers: list[ProviderStatusItem]
    timestamp: str


class KnowledgeDatasetItem(BaseModel):
    """Status for a single reference-knowledge dataset.

    ``loaded`` reflects whether the dataset is resolved in memory *now*; some
    providers load their bundled dataset lazily on first use, so an enabled,
    offline dataset may report ``loaded=false`` at startup yet still be
    ``healthy`` (it loads on demand).
    """

    name: str
    display_name: str
    enabled: bool
    healthy: bool
    loaded: bool
    dataset_version: str | None
    release_date: str | None
    last_updated: str | None
    offline: bool
    entity_types: list[str]


class KnowledgeHealth(BaseModel):
    """Reference-knowledge dataset status (offline; no network calls)."""

    status: str
    loaded: int
    total: int
    datasets: list[KnowledgeDatasetItem]
    timestamp: str


class AIHealth(BaseModel):
    """AI subsystem status. The only check that may touch the network."""

    status: str  # "disabled" | "ok" | "unavailable" | "error"
    enabled: bool
    provider: str
    model: str | None
    reachable: bool
    model_available: bool | None
    detail: str | None
    timestamp: str


class BuildInfo(BaseModel):
    commit: str | None
    timestamp: str | None


class VersionInfo(BaseModel):
    """Component versions for support and reproducibility."""

    platform: str
    api: str
    reasoning_engine: str
    build: BuildInfo


router = APIRouter(tags=["health"])


# --------------------------------------------------------------------------- #
# Liveness / readiness
# --------------------------------------------------------------------------- #


@router.get("/health", response_model=HealthStatus)
def health() -> HealthStatus:
    """Liveness probe — always ``200`` while the process is up.

    Cheap and dependency-free: suitable for a container/orchestrator liveness
    check. It reports uptime and the running version but never inspects providers
    or the network.
    """
    return HealthStatus(
        version=PLATFORM_VERSION,
        uptime_seconds=_uptime_seconds(),
        started_at=_STARTED_AT.isoformat(),
        timestamp=_now_iso(),
    )


@router.get("/ready", response_model=Readiness)
def ready(response: Response) -> Readiness:
    """Readiness probe — ``200`` when the deterministic core can serve, else ``503``.

    Readiness reflects the *core, offline* product: detection, the reasoning
    engine, and the bundled knowledge datasets. It deliberately ignores
    threat-intelligence credentials and the AI layer — both are optional
    enrichment whose absence must never take the service out of rotation.
    """
    loaded = _loaded_dataset_count()
    checks = [
        ReadinessCheck(
            name="detection_engine",
            ready=True,
            detail="Deterministic entity detection is available.",
        ),
        ReadinessCheck(
            name="reasoning_engine",
            ready=bool(ENGINE_VERSION),
            detail=f"Reasoning Engine v{ENGINE_VERSION} loaded.",
        ),
        ReadinessCheck(
            name="knowledge_base",
            ready=loaded > 0,
            detail=f"{loaded}/{len(_REF_REGISTRY)} reference dataset(s) loaded.",
        ),
    ]
    is_ready = all(check.ready for check in checks)
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return Readiness(ready=is_ready, checks=checks, timestamp=_now_iso())


# --------------------------------------------------------------------------- #
# Subsystem health
# --------------------------------------------------------------------------- #


@router.get("/health/providers", response_model=ProvidersHealth)
def providers_health() -> ProvidersHealth:
    """Threat-intelligence provider configuration — **never** calls a provider.

    For each registered TI provider, reports whether it is enabled, whether it
    requires credentials, and whether those credentials are present in the
    environment. This consumes no API quota. Overall status is ``ok`` when every
    enabled, auth-requiring provider has a key, otherwise ``degraded`` (a normal
    state — ThreatLens runs fully on offline knowledge without any TI keys).
    """
    items: list[ProviderStatusItem] = []
    for provider in _TI_REGISTRY.providers:
        meta = provider.metadata
        configured = _provider_configured(meta.name, requires_auth=meta.requires_auth)
        items.append(
            ProviderStatusItem(
                name=meta.name,
                display_name=meta.display_name,
                enabled=meta.enabled,
                requires_auth=meta.requires_auth,
                configured=configured,
                entity_types=sorted(t.value for t in meta.supported_entity_types),
            )
        )

    configured_count = sum(1 for item in items if item.configured)
    missing = [i for i in items if i.enabled and i.requires_auth and not i.configured]
    return ProvidersHealth(
        status="ok" if not missing else "degraded",
        configured=configured_count,
        total=len(items),
        providers=items,
        timestamp=_now_iso(),
    )


@router.get("/health/knowledge", response_model=KnowledgeHealth)
def knowledge_health() -> KnowledgeHealth:
    """Reference-knowledge dataset status — offline, **never** calls the network.

    Reports each bundled dataset's version/provenance and whether it loaded
    successfully (inferred from resolved metadata; datasets are loaded once at
    startup). Overall status is ``ok`` when every dataset loaded, else
    ``degraded``.
    """
    items: list[KnowledgeDatasetItem] = []
    for provider in _REF_REGISTRY.providers:
        meta = provider.metadata
        loaded = meta.dataset_version is not None
        # An enabled, bundled (offline) dataset is healthy even before its lazy
        # first-use load; only a disabled or non-offline-yet-unloaded source is not.
        healthy = loaded or (meta.enabled and meta.offline)
        items.append(
            KnowledgeDatasetItem(
                name=meta.name,
                display_name=meta.display_name,
                enabled=meta.enabled,
                healthy=healthy,
                loaded=loaded,
                dataset_version=meta.dataset_version,
                release_date=meta.release_date,
                last_updated=meta.last_updated.isoformat() if meta.last_updated else None,
                offline=meta.offline,
                entity_types=sorted(t.value for t in meta.supported_entity_types),
            )
        )

    loaded_count = sum(1 for item in items if item.loaded)
    healthy_count = sum(1 for item in items if item.healthy)
    return KnowledgeHealth(
        status="ok" if healthy_count == len(items) else "degraded",
        loaded=loaded_count,
        total=len(items),
        datasets=items,
        timestamp=_now_iso(),
    )


@router.get("/health/ai", response_model=AIHealth)
async def ai_health() -> AIHealth:
    """AI subsystem status — the only endpoint that may touch the network.

    When AI is disabled (the default) this returns ``disabled`` without any
    network call. When enabled, it performs a single lightweight reachability
    probe against the Ollama server (``GET /api/tags``) — never a model
    generation, so no tokens are spent — and reports whether the configured model
    is present. Any failure is reported as a friendly, non-fatal state; the
    endpoint always returns ``200`` and never leaks a stack trace.
    """
    return await _probe_ai(AISettings.from_env())


@router.get("/version", response_model=VersionInfo)
def version() -> VersionInfo:
    """Component versions for support and reproducibility (read-only)."""
    return VersionInfo(
        platform=PLATFORM_VERSION,
        api=API_VERSION,
        reasoning_engine=ENGINE_VERSION,
        build=BuildInfo(
            commit=_first_env(_BUILD_COMMIT_ENVS),
            timestamp=_first_env(_BUILD_TIME_ENVS),
        ),
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _uptime_seconds() -> float:
    return round(time.monotonic() - _STARTED_MONO, 3)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _loaded_dataset_count() -> int:
    return sum(1 for p in _REF_REGISTRY.providers if p.metadata.dataset_version is not None)


def _provider_configured(name: str, *, requires_auth: bool) -> bool:
    """Whether a provider's credentials are present (read-only; no provider call).

    A provider that needs no auth is always "configured". abuse.ch providers
    share one key (resolved by the provider's own helper); the rest map to a
    single env var.
    """
    if not requires_auth:
        return True
    if name in _ABUSE_CH_PROVIDERS:
        return abuse_ch_auth_key() is not None
    env = _DIRECT_KEY_ENV.get(name)
    return bool(os.getenv(env)) if env else False


def _first_env(names: tuple[str, ...]) -> str | None:
    for candidate in names:
        value = os.getenv(candidate)
        if value and value.strip():
            return value.strip()
    return None


async def _probe_ai(settings: AISettings, http: HttpClient | None = None) -> AIHealth:
    """Probe AI reachability without spending tokens (see :func:`ai_health`).

    ``http`` is injectable so tests can drive the probe against a mock transport;
    production passes ``None`` and a short-timeout, no-retry client is built.
    """
    now = _now_iso()
    if not settings.enabled:
        return AIHealth(
            status="disabled",
            enabled=False,
            provider=settings.provider,
            model=None,
            reachable=False,
            model_available=None,
            detail="The AI explanation layer is disabled.",
            timestamp=now,
        )
    if settings.provider != "ollama":
        return AIHealth(
            status="unavailable",
            enabled=True,
            provider=settings.provider,
            model=None,
            reachable=False,
            model_available=None,
            detail=f"Provider {settings.provider!r} is enabled but not supported.",
            timestamp=now,
        )

    url = settings.ollama_url.rstrip("/")
    model = settings.ollama_model
    client = http or HttpClient(timeout=_AI_PROBE_TIMEOUT, max_retries=0)
    try:
        response = await client.get(f"{url}/api/tags")
    except ProviderHttpError as exc:
        return _ai_unreachable(settings, "unavailable", _short(exc) or "provider unreachable", now)
    except Exception:  # defensive: a probe must never raise
        return _ai_unreachable(settings, "error", "unexpected error probing the AI provider", now)

    if response.status_code != 200:
        detail = f"Ollama responded with HTTP {response.status_code}."
        return _ai_unreachable(settings, "unavailable", detail, now)

    return AIHealth(
        status="ok",
        enabled=True,
        provider="ollama",
        model=model,
        reachable=True,
        model_available=_model_present(response, model),
        detail=None,
        timestamp=now,
    )


def _ai_unreachable(settings: AISettings, status_: str, detail: str, now: str) -> AIHealth:
    return AIHealth(
        status=status_,
        enabled=True,
        provider=settings.provider,
        model=settings.ollama_model,
        reachable=False,
        model_available=None,
        detail=detail,
        timestamp=now,
    )


def _model_present(response: Any, model: str) -> bool | None:
    """Whether ``model`` appears in an Ollama ``/api/tags`` body (``None`` if unclear)."""
    try:
        payload = response.json()
        models = payload.get("models", [])
    except (ValueError, AttributeError, TypeError):
        return None
    if not isinstance(models, list):
        return None
    names = {m.get("name", "") for m in models if isinstance(m, dict)}
    # Tolerate an untagged model name (Ollama stores it as "<model>:latest").
    return model in names or (":" not in model and f"{model}:latest" in names)


def _short(exc: Exception) -> str:
    """A concise, single-line error detail (never a stack trace)."""
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
    return text[:200]
