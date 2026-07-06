"""Tests for GET /api/v1/identity — the Phase 6.0 framework-status probe."""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.identity import IDENTITY_FRAMEWORK_VERSION

client = TestClient(app)


def test_returns_200_and_ready_status() -> None:
    res = client.get("/api/v1/identity")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ready"


def test_reports_zero_providers_in_phase_6_0() -> None:
    body = client.get("/api/v1/identity").json()
    assert body["providers_registered"] == 0
    assert body["message"] == "No providers configured"


def test_reports_framework_version() -> None:
    body = client.get("/api/v1/identity").json()
    assert body["framework_version"] == IDENTITY_FRAMEWORK_VERSION


def test_response_shape_is_exactly_the_documented_fields() -> None:
    body = client.get("/api/v1/identity").json()
    assert set(body) == {"status", "message", "framework_version", "providers_registered"}


def test_is_a_pure_get_with_no_query_params_required() -> None:
    # No body, no query string — a readiness probe, not an entity lookup.
    res = client.get("/api/v1/identity")
    assert res.status_code == 200


def test_is_deterministic_across_calls() -> None:
    first = client.get("/api/v1/identity").json()
    second = client.get("/api/v1/identity").json()
    assert first == second


def test_never_invokes_the_investigation_path(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The identity status endpoint must never trigger a real investigation."""
    from threatlens.providers.base import IntelligenceProvider

    async def boom(self: object, entity: object) -> object:
        raise AssertionError("identity status must never invoke a TI provider lookup")

    monkeypatch.setattr(IntelligenceProvider, "safe_search", boom)
    monkeypatch.setattr(IntelligenceProvider, "search", boom)

    assert client.get("/api/v1/identity").status_code == 200
