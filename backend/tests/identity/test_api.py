"""Tests for GET /api/v1/identity — the Phase 6.0 framework-status probe."""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.identity import IDENTITY_FRAMEWORK_VERSION
from threatlens.providers.http import HttpResponse

client = TestClient(app)


def test_returns_200_and_ready_status() -> None:
    res = client.get("/api/v1/identity")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ready"


def test_reports_registered_provider() -> None:
    body = client.get("/api/v1/identity").json()
    assert body["providers_registered"] == 1
    assert body["message"] == "1 provider(s) registered"


def test_reports_framework_version() -> None:
    body = client.get("/api/v1/identity").json()
    assert body["framework_version"] == IDENTITY_FRAMEWORK_VERSION


def test_response_shape_is_exactly_the_documented_fields() -> None:
    body = client.get("/api/v1/identity").json()
    assert set(body) == {
        "status",
        "message",
        "framework_version",
        "providers_registered",
        "enabled",
        "providers",
        "summary",
    }


def test_reports_provider_configuration_without_secret() -> None:
    body = client.get("/api/v1/identity").json()
    assert body["providers"][0]["name"] == "hibp"
    assert "api_key" not in body["providers"][0]


def test_is_a_pure_get_with_no_query_params_required() -> None:
    # No body, no query string — a readiness probe, not an entity lookup.
    res = client.get("/api/v1/identity")
    assert res.status_code == 200


def test_is_deterministic_across_calls() -> None:
    first = client.get("/api/v1/identity").json()
    second = client.get("/api/v1/identity").json()
    assert first == second


def test_email_check_rejects_non_email() -> None:
    response = client.post("/api/v1/identity/email/check", json={"email": "not-an-email"})
    assert response.status_code == 422


def test_disabled_email_check_returns_a_descriptive_empty_summary() -> None:
    response = client.post(
        "/api/v1/identity/email/check", json={"email": "analyst@example.com"}
    )
    assert response.status_code == 200
    assert response.json()["cache_status"] == "disabled"
    assert response.json()["summary"]["entity_value"] == "analyst@example.com"


def test_password_range_rejects_a_full_hash() -> None:
    response = client.get("/api/v1/identity/password-range/ABCDE12345")
    assert response.status_code == 422


def test_password_range_returns_only_valid_suffixes(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from threatlens.api.routes import identity

    async def fake_get(*args: object, **kwargs: object) -> HttpResponse:
        return HttpResponse(
            status_code=200,
            text=f"{'A' * 35}:42\nmalformed\n{'B' * 35}:not-a-number",
        )

    monkeypatch.setattr(identity._password_client, "get", fake_get)
    monkeypatch.setattr(identity, "_password_request_allowed", lambda: True)
    response = client.get("/api/v1/identity/password-range/abcde")
    assert response.status_code == 200
    assert response.json()["prefix"] == "ABCDE"
    assert response.json()["suffixes"] == [{"suffix": "A" * 35, "count": 42}]


def test_never_invokes_the_investigation_path(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The identity status endpoint must never trigger a real investigation."""
    from threatlens.providers.base import IntelligenceProvider

    async def boom(self: object, entity: object) -> object:
        raise AssertionError("identity status must never invoke a TI provider lookup")

    monkeypatch.setattr(IntelligenceProvider, "safe_search", boom)
    monkeypatch.setattr(IntelligenceProvider, "search", boom)

    assert client.get("/api/v1/identity").status_code == 200
