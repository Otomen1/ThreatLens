"""Tests for GET /api/v1/correlation — the Phase 7.0 framework-status probe."""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.correlation import CORRELATION_FRAMEWORK_VERSION

client = TestClient(app)


def test_returns_200_and_ready_status() -> None:
    res = client.get("/api/v1/correlation")
    assert res.status_code == 200
    assert res.json()["status"] == "ready"


def test_reports_the_seed_rule_count() -> None:
    body = client.get("/api/v1/correlation").json()
    assert body["rules_registered"] == 12
    assert body["message"] == "12 correlation rule(s) registered"


def test_reports_framework_version() -> None:
    body = client.get("/api/v1/correlation").json()
    assert body["framework_version"] == CORRELATION_FRAMEWORK_VERSION


def test_response_shape_is_exactly_the_documented_fields() -> None:
    body = client.get("/api/v1/correlation").json()
    assert set(body) == {"status", "message", "framework_version", "rules_registered"}


def test_is_deterministic_across_calls() -> None:
    assert client.get("/api/v1/correlation").json() == client.get("/api/v1/correlation").json()


def test_never_invokes_a_provider_or_investigation(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The correlation status endpoint must never trigger a TI provider lookup."""
    from threatlens.providers.base import IntelligenceProvider

    async def boom(self: object, entity: object) -> object:
        raise AssertionError("correlation status must never invoke a TI provider lookup")

    monkeypatch.setattr(IntelligenceProvider, "safe_search", boom)
    monkeypatch.setattr(IntelligenceProvider, "search", boom)

    assert client.get("/api/v1/correlation").status_code == 200
