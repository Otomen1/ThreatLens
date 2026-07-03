"""In-memory operational counters for the Operational Dashboard (v1).

This module is the *only* place runtime counters live, and it never calls a
provider, the Investigation Engine, the Reasoning Engine, the Detection
Engine, the Detection Knowledge Library, or the AI service. Callers in
``api/app.py`` record a counter update *after* an existing route has already
computed its (unchanged) response — recording is a pure side effect on data
that already exists; it never influences what a route returns.

Process-local, in-memory, reset on restart by design: a dashboard v1 has no
monitoring stack, so incremental counters are the whole strategy (see
``docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md``). A single lock
guards every mutation; each recorder call is O(1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class CallCounter:
    """Running totals for one thing that is called and can succeed or fail."""

    requests: int = 0
    successes: int = 0
    failures: int = 0
    latency_total_ms: float = 0.0
    latency_min_ms: float | None = None
    latency_max_ms: float | None = None
    cache_hits: int = 0
    cache_misses: int = 0
    last_request_at: str | None = None
    last_success_at: str | None = None

    def record(
        self, *, success: bool, latency_ms: float, cache_hit: bool | None = None
    ) -> None:
        self.requests += 1
        self.last_request_at = _now()
        if success:
            self.successes += 1
            self.last_success_at = self.last_request_at
        else:
            self.failures += 1
        self.latency_total_ms += latency_ms
        self.latency_min_ms = (
            latency_ms if self.latency_min_ms is None else min(self.latency_min_ms, latency_ms)
        )
        self.latency_max_ms = (
            latency_ms if self.latency_max_ms is None else max(self.latency_max_ms, latency_ms)
        )
        if cache_hit is True:
            self.cache_hits += 1
        elif cache_hit is False:
            self.cache_misses += 1

    @property
    def success_rate(self) -> float | None:
        return round(100 * self.successes / self.requests, 1) if self.requests else None

    @property
    def avg_latency_ms(self) -> float | None:
        return round(self.latency_total_ms / self.requests, 1) if self.requests else None


@dataclass
class RunningAverage:
    """A running mean + min/max for a scalar metric (durations, counts, sizes)."""

    count: int = 0
    total: float = 0.0
    minimum: float | None = None
    maximum: float | None = None

    def add(self, value: float) -> None:
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)

    @property
    def average(self) -> float | None:
        return round(self.total / self.count, 2) if self.count else None


@dataclass
class MetricsRegistry:
    """Process-wide counters for the Operational Dashboard's usage endpoint."""

    ti_providers: dict[str, CallCounter] = field(default_factory=dict)
    kb_providers: dict[str, CallCounter] = field(default_factory=dict)
    ai: CallCounter = field(default_factory=CallCounter)
    ai_prompt_chars: RunningAverage = field(default_factory=RunningAverage)
    ai_completion_chars: RunningAverage = field(default_factory=RunningAverage)
    detection_by_language: dict[str, int] = field(default_factory=dict)
    detection_generation_ms: RunningAverage = field(default_factory=RunningAverage)
    detection_last_generated_at: str | None = None
    dkl_queries: CallCounter = field(default_factory=CallCounter)
    investigation_duration_ms: RunningAverage = field(default_factory=RunningAverage)
    investigation_findings: RunningAverage = field(default_factory=RunningAverage)
    investigation_recommendations: RunningAverage = field(default_factory=RunningAverage)
    investigation_confidence: RunningAverage = field(default_factory=RunningAverage)

    def __post_init__(self) -> None:
        self._lock = Lock()

    def reset(self) -> None:
        """Clear all counters in place (tests only — the running app never calls this)."""
        with self._lock:
            self.ti_providers.clear()
            self.kb_providers.clear()
            self.ai = CallCounter()
            self.ai_prompt_chars = RunningAverage()
            self.ai_completion_chars = RunningAverage()
            self.detection_by_language.clear()
            self.detection_generation_ms = RunningAverage()
            self.detection_last_generated_at = None
            self.dkl_queries = CallCounter()
            self.investigation_duration_ms = RunningAverage()
            self.investigation_findings = RunningAverage()
            self.investigation_recommendations = RunningAverage()
            self.investigation_confidence = RunningAverage()

    def record_ti(self, provider: str, *, success: bool, latency_ms: float) -> None:
        """Record one TI provider's outcome for the enclosing investigation.

        ``latency_ms`` is the *enclosing* ``/investigate`` call's wall-clock
        time (providers run concurrently, so a per-provider network timing is
        not observable without instrumenting inside the Investigation Engine,
        which this dashboard never does — see the architecture doc).
        """
        with self._lock:
            self.ti_providers.setdefault(provider, CallCounter()).record(
                success=success, latency_ms=latency_ms
            )

    def record_kb(self, provider: str, *, success: bool, latency_ms: float) -> None:
        """Same as :meth:`record_ti`, for reference/knowledge providers."""
        with self._lock:
            self.kb_providers.setdefault(provider, CallCounter()).record(
                success=success, latency_ms=latency_ms
            )

    def record_ai(
        self, *, success: bool, latency_ms: float, prompt_chars: int, completion_chars: int
    ) -> None:
        with self._lock:
            self.ai.record(success=success, latency_ms=latency_ms)
            self.ai_prompt_chars.add(prompt_chars)
            self.ai_completion_chars.add(completion_chars)

    def record_detection_generation(self, *, languages: list[str], latency_ms: float) -> None:
        with self._lock:
            for language in languages:
                self.detection_by_language[language] = (
                    self.detection_by_language.get(language, 0) + 1
                )
            self.detection_generation_ms.add(latency_ms)
            self.detection_last_generated_at = _now()

    def record_dkl_query(self, *, success: bool, latency_ms: float) -> None:
        with self._lock:
            self.dkl_queries.record(success=success, latency_ms=latency_ms)

    def record_investigation(
        self,
        *,
        duration_ms: float,
        findings: int,
        recommendations: int,
        confidence: float | None,
    ) -> None:
        with self._lock:
            self.investigation_duration_ms.add(duration_ms)
            self.investigation_findings.add(findings)
            self.investigation_recommendations.add(recommendations)
            if confidence is not None:
                self.investigation_confidence.add(confidence)


# One process-wide instance, mirroring how `api/app.py` builds its other
# singleton services (investigation service, AI service, registries).
registry = MetricsRegistry()
