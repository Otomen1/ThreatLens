"""Tests for GET /api/v1/exposure — framework/provider status, and real lookups."""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.exposure import EXPOSURE_FRAMEWORK_VERSION, ExposureRegistry, ExposureService

# threatlens.api's __init__ does `from .app import app`, which rebinds the
# `app` attribute on the `threatlens.api` package to the FastAPI instance —
# so `import threatlens.api.app as x` (an attribute-chain lookup) would
# resolve to that instance, not the module. importlib bypasses the package
# namespace entirely and returns the actual module.
app_module = importlib.import_module("threatlens.api.app")

client = TestClient(app)


def test_returns_200_and_ready_status() -> None:
    res = client.get("/api/v1/exposure")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ready"


def test_reports_shodan_registered_by_default() -> None:
    """Phase 5.1 registers Shodan; the default registry reflects that."""
    body = client.get("/api/v1/exposure").json()
    assert body["providers_registered"] == 1
    assert body["message"] == "1 provider(s) registered"


def test_reports_framework_version() -> None:
    body = client.get("/api/v1/exposure").json()
    assert body["framework_version"] == EXPOSURE_FRAMEWORK_VERSION


def test_response_shape_is_exactly_the_documented_fields() -> None:
    body = client.get("/api/v1/exposure").json()
    assert set(body) == {
        "status",
        "message",
        "framework_version",
        "providers_registered",
        "providers",
        "summary",
    }


def test_is_a_pure_get_with_no_query_params_required() -> None:
    # No body, no query string — value is optional, so this stays a readiness probe.
    res = client.get("/api/v1/exposure")
    assert res.status_code == 200
    assert res.json()["summary"] is None


def test_never_invokes_the_investigation_path(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The exposure status endpoint must never trigger a real investigation."""
    from threatlens.providers.base import IntelligenceProvider

    async def boom(self: object, entity: object) -> object:
        raise AssertionError("exposure status must never invoke a TI provider lookup")

    monkeypatch.setattr(IntelligenceProvider, "safe_search", boom)
    monkeypatch.setattr(IntelligenceProvider, "search", boom)

    assert client.get("/api/v1/exposure").status_code == 200


def test_reports_shodan_provider_health() -> None:
    """No SHODAN_API_KEY configured in tests — health degrades, never crashes."""
    body = client.get("/api/v1/exposure").json()
    assert body["providers"] == [
        {
            "name": "shodan",
            "display_name": "Shodan",
            "status": "degraded",
            "detail": "API key not configured",
        }
    ]


def test_value_param_runs_a_real_lookup_and_returns_a_summary() -> None:
    res = client.get("/api/v1/exposure", params={"value": "8.8.8.8"})
    assert res.status_code == 200
    body = res.json()
    summary = body["summary"]
    assert summary is not None
    assert summary["entity_type"] == "ipv4"
    assert summary["entity_value"] == "8.8.8.8"
    assert summary["findings"][0]["provider"] == "shodan"
    # No API key configured in tests: a structured auth failure, never a crash or a real request.
    assert summary["findings"][0]["status"] == "unauthorized"


def test_blank_value_param_is_treated_as_absent() -> None:
    res = client.get("/api/v1/exposure", params={"value": "   "})
    assert res.status_code == 200
    assert res.json()["summary"] is None


def test_disabled_registry_yields_a_valid_empty_summary_not_an_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A registry with nothing routable must never fail the endpoint."""
    empty_registry = ExposureRegistry()
    monkeypatch.setattr(app_module, "_exposure_registry", empty_registry)
    monkeypatch.setattr(app_module, "_exposure_service", ExposureService(empty_registry))

    res = client.get("/api/v1/exposure", params={"value": "8.8.8.8"})
    assert res.status_code == 200
    body = res.json()
    assert body["providers_registered"] == 0
    assert body["providers"] == []
    assert body["summary"]["findings"] == []
    assert body["summary"]["statistics"]["providers_queried"] == 0
