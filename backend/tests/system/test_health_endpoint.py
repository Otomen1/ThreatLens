"""Integration tests for GET /api/v1/system/health (Section 1)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.detection_library.service import DetectionKnowledgeService

client = TestClient(app)

_EXPECTED_SERVICES = {
    "backend",
    "api",
    "threat_intelligence",
    "knowledge",
    "ai",
    "detection_engine",
    "detection_knowledge",
}


def test_lists_every_required_service() -> None:
    body = client.get("/api/v1/system/health").json()
    names = {s["name"] for s in body["services"]}
    assert names == _EXPECTED_SERVICES
    for service in body["services"]:
        assert service["status"] in {"healthy", "degraded", "offline", "disabled"}
        assert service["detail"]  # never an empty/missing detail
        assert service["display_name"]


def test_ai_disabled_by_default() -> None:
    body = client.get("/api/v1/system/health").json()
    ai = next(s for s in body["services"] if s["name"] == "ai")
    assert ai["status"] == "disabled"


def test_detection_engine_is_healthy_with_registered_generators() -> None:
    body = client.get("/api/v1/system/health").json()
    engine = next(s for s in body["services"] if s["name"] == "detection_engine")
    assert engine["status"] == "healthy"
    assert "generator" in engine["detail"]


def test_detection_knowledge_is_healthy_with_indexed_rules() -> None:
    body = client.get("/api/v1/system/health").json()
    dkl = next(s for s in body["services"] if s["name"] == "detection_knowledge")
    assert dkl["status"] == "healthy"
    assert "rule" in dkl["detail"]


def test_threat_intelligence_degraded_when_no_keys_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var in (
        "ABUSE_CH_AUTH_KEY",
        "MALWAREBAZAAR_AUTH_KEY",
        "URLHAUS_AUTH_KEY",
        "ABUSEIPDB_API_KEY",
        "OTX_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    body = client.get("/api/v1/system/health").json()
    ti = next(s for s in body["services"] if s["name"] == "threat_intelligence")
    assert ti["status"] == "degraded"
    # Overall rolls up to the worst non-disabled state (AI is excluded — it's
    # disabled, not degraded/offline).
    assert body["status"] == "degraded"


def test_never_leaks_internal_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken dependency must degrade gracefully, never surface a stack trace."""

    def boom(self: DetectionKnowledgeService) -> object:
        raise RuntimeError("simulated cache corruption with a secret path /var/x")

    monkeypatch.setattr(DetectionKnowledgeService, "stats", boom)
    res = client.get("/api/v1/system/health")
    assert res.status_code == 200
    body = res.json()
    dkl = next(s for s in body["services"] if s["name"] == "detection_knowledge")
    assert dkl["status"] == "degraded"
    assert "Traceback" not in res.text
    assert "secret path" not in res.text  # exception message never echoed back


def test_never_invokes_a_provider_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    from threatlens.providers.base import IntelligenceProvider
    from threatlens.reference.base import ReferenceProvider

    async def fail(self: object, entity: object) -> object:
        raise AssertionError("the dashboard must never run a provider lookup")

    monkeypatch.setattr(IntelligenceProvider, "safe_search", fail)
    monkeypatch.setattr(IntelligenceProvider, "search", fail)
    monkeypatch.setattr(ReferenceProvider, "safe_lookup", fail)
    monkeypatch.setattr(ReferenceProvider, "lookup", fail)

    assert client.get("/api/v1/system/health").status_code == 200
