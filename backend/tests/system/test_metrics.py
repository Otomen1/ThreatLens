"""Unit tests for the in-memory operational counters (Operational Dashboard v1)."""

from __future__ import annotations

import pytest

from threatlens.system.metrics import CallCounter, MetricsRegistry, RunningAverage


class TestCallCounter:
    def test_starts_empty(self) -> None:
        c = CallCounter()
        assert c.requests == 0
        assert c.success_rate is None
        assert c.avg_latency_ms is None
        assert c.last_request_at is None

    def test_records_success(self) -> None:
        c = CallCounter()
        c.record(success=True, latency_ms=100.0)
        assert c.requests == 1
        assert c.successes == 1
        assert c.failures == 0
        assert c.success_rate == 100.0
        assert c.avg_latency_ms == 100.0
        assert c.last_request_at is not None
        assert c.last_success_at == c.last_request_at

    def test_records_failure(self) -> None:
        c = CallCounter()
        c.record(success=False, latency_ms=50.0)
        assert c.requests == 1
        assert c.failures == 1
        assert c.success_rate == 0.0
        assert c.last_success_at is None  # a failure never sets last_success_at

    def test_success_rate_averages_across_calls(self) -> None:
        c = CallCounter()
        c.record(success=True, latency_ms=10.0)
        c.record(success=True, latency_ms=20.0)
        c.record(success=False, latency_ms=30.0)
        assert c.requests == 3
        assert c.success_rate == pytest.approx(66.7, abs=0.1)
        assert c.avg_latency_ms == 20.0
        assert c.latency_min_ms == 10.0
        assert c.latency_max_ms == 30.0

    def test_cache_hits_and_misses_are_independent_of_success(self) -> None:
        c = CallCounter()
        c.record(success=True, latency_ms=1.0, cache_hit=True)
        c.record(success=True, latency_ms=1.0, cache_hit=False)
        c.record(success=True, latency_ms=1.0)  # neither hit nor miss
        assert c.cache_hits == 1
        assert c.cache_misses == 1
        assert c.requests == 3


class TestRunningAverage:
    def test_starts_empty(self) -> None:
        a = RunningAverage()
        assert a.count == 0
        assert a.average is None
        assert a.minimum is None
        assert a.maximum is None

    def test_computes_average_min_max(self) -> None:
        a = RunningAverage()
        for value in (10, 20, 30):
            a.add(value)
        assert a.count == 3
        assert a.average == 20.0
        assert a.minimum == 10
        assert a.maximum == 30


class TestMetricsRegistry:
    def test_ti_and_kb_providers_are_tracked_independently(self) -> None:
        registry = MetricsRegistry()
        registry.record_ti("abuseipdb", success=True, latency_ms=100.0)
        registry.record_ti("otx", success=False, latency_ms=50.0)
        registry.record_kb("mitre_attack", success=True, latency_ms=5.0)

        assert registry.ti_providers["abuseipdb"].requests == 1
        assert registry.ti_providers["otx"].failures == 1
        assert registry.kb_providers["mitre_attack"].successes == 1
        assert "abuseipdb" not in registry.kb_providers

    def test_detection_generation_counts_by_language(self) -> None:
        registry = MetricsRegistry()
        registry.record_detection_generation(languages=["sigma", "yara", "sigma"], latency_ms=12.0)
        assert registry.detection_by_language == {"sigma": 2, "yara": 1}
        assert registry.detection_generation_ms.average == 12.0
        assert registry.detection_last_generated_at is not None

    def test_investigation_stats_skip_missing_confidence(self) -> None:
        registry = MetricsRegistry()
        registry.record_investigation(
            duration_ms=100.0, findings=2, recommendations=1, confidence=None
        )
        assert registry.investigation_duration_ms.count == 1
        assert registry.investigation_confidence.count == 0  # None is never counted

    def test_ai_counter_tracks_prompt_and_completion_sizes(self) -> None:
        registry = MetricsRegistry()
        registry.record_ai(success=True, latency_ms=200.0, prompt_chars=500, completion_chars=300)
        assert registry.ai.requests == 1
        assert registry.ai_prompt_chars.average == 500
        assert registry.ai_completion_chars.average == 300
