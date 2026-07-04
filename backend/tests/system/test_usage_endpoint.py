"""Integration tests for GET /api/v1/system/usage (Section 2)."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app, get_investigation_service
from threatlens.entities.types import EntityType
from threatlens.investigation import InvestigationService
from threatlens.providers import AggregatedResult, ProviderSummary
from threatlens.providers.results import ResultStatus

client = TestClient(app)


@pytest.fixture()
def mock_investigation() -> Iterator[MagicMock]:
    """Overrides the investigation service with canned, offline provider results."""
    mock_svc = MagicMock(spec=InvestigationService)
    mock_svc.investigate = AsyncMock(
        return_value=(
            AggregatedResult(
                entity_type=EntityType.IPV4,
                entity_value="8.8.8.8",
                providers=[
                    ProviderSummary(provider="abuseipdb", status=ResultStatus.OK),
                    ProviderSummary(provider="otx", status=ResultStatus.ERROR),
                ],
            ),
            AggregatedResult(entity_type=EntityType.IPV4, entity_value="8.8.8.8", providers=[]),
        )
    )
    app.dependency_overrides[get_investigation_service] = lambda: mock_svc
    yield mock_svc
    app.dependency_overrides.pop(get_investigation_service, None)


def test_lists_every_configured_ti_and_kb_provider_even_with_zero_requests() -> None:
    body = client.get("/api/v1/system/usage").json()
    ti_names = {p["name"] for p in body["threat_intelligence"]}
    assert ti_names == {"malwarebazaar", "urlhaus", "abuseipdb", "otx"}
    for provider in body["threat_intelligence"]:
        assert provider["requests"] == 0
        assert provider["success_rate"] is None
        assert provider["avg_latency_ms"] is None
    kb_names = {p["name"] for p in body["knowledge"]}
    assert {"mitre_attack", "nvd", "cwe", "capec"} <= kb_names


def test_investigate_updates_provider_and_investigation_counters(
    mock_investigation: MagicMock,
) -> None:
    res = client.post("/api/v1/investigate", json={"query": "8.8.8.8"})
    assert res.status_code == 200

    body = client.get("/api/v1/system/usage").json()
    abuseipdb = next(p for p in body["threat_intelligence"] if p["name"] == "abuseipdb")
    otx = next(p for p in body["threat_intelligence"] if p["name"] == "otx")

    assert abuseipdb["requests"] == 1
    assert abuseipdb["successful"] == 1
    assert otx["requests"] == 1
    assert otx["failed"] == 1
    assert abuseipdb["avg_latency_ms"] is not None and abuseipdb["avg_latency_ms"] >= 0

    assert body["investigations"]["executed"] == 1
    assert body["investigations"]["avg_duration_ms"] is not None


def test_ai_usage_reflects_disabled_default() -> None:
    body = client.get("/api/v1/system/usage").json()
    ai = body["ai"]
    assert ai["enabled"] is False
    assert ai["model"] is None
    assert ai["requests"] == 0
    assert ai["estimated_tokens"] is None
    assert ai["estimated_cost_usd"] is None  # never estimated for Ollama


def test_detection_knowledge_reports_current_library_state() -> None:
    body = client.get("/api/v1/system/usage").json()
    dkl = body["detection_knowledge"]
    assert dkl["rules_indexed"] > 0
    assert dkl["library_version"]
    assert dkl["sync_status"]


def test_detection_engineering_starts_at_zero() -> None:
    body = client.get("/api/v1/system/usage").json()
    detection = body["detection_engineering"]
    assert detection["generated_total"] == 0
    assert detection["by_language"] == {}
    assert detection["last_generated_at"] is None


def test_no_secrets_in_usage_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "totally-secret-value-12345")
    monkeypatch.setenv("OTX_API_KEY", "another-secret-999")
    res = client.get("/api/v1/system/usage")
    assert "totally-secret-value-12345" not in res.text
    assert "another-secret-999" not in res.text
