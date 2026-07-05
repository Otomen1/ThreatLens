"""Tests for GET /api/v1/exposure — framework/provider status, and real lookups."""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.exposure import (
    EXPOSURE_FRAMEWORK_VERSION,
    CensysProvider,
    ExposureRegistry,
    ExposureService,
    ShodanProvider,
)

# threatlens.api's __init__ does `from .app import app`, which rebinds the
# `app` attribute on the `threatlens.api` package to the FastAPI instance —
# so `import threatlens.api.app as x` (an attribute-chain lookup) would
# resolve to that instance, not the module. importlib bypasses the package
# namespace entirely and returns the actual module.
app_module = importlib.import_module("threatlens.api.app")

client = TestClient(app)


def _use_registry(monkeypatch, registry: ExposureRegistry) -> None:  # type: ignore[no-untyped-def]
    """Swap the app's process-wide registry/service for an explicitly-built one.

    The real singletons are constructed once at module-import time from
    whatever environment (including a local ``.env``) happened to be present
    then — a per-test env fixture can't retroactively change that. Tests
    that need a *specific*, known provider-credential state (rather than
    "whatever this machine's ``.env`` contains") inject a fresh registry
    instead, the same way ``test_disabled_registry_...`` already does.
    """
    monkeypatch.setattr(app_module, "_exposure_registry", registry)
    monkeypatch.setattr(app_module, "_exposure_service", ExposureService(registry))


def _unconfigured_registry() -> ExposureRegistry:
    registry = ExposureRegistry()
    registry.register(CensysProvider(api_id=None, api_secret=None))
    registry.register(ShodanProvider(api_key=None))
    return registry


def test_returns_200_and_ready_status() -> None:
    res = client.get("/api/v1/exposure")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ready"


def test_reports_shodan_and_censys_registered_by_default() -> None:
    """Phase 5.1 registered Shodan; Phase 5.2 adds Censys — both by default."""
    body = client.get("/api/v1/exposure").json()
    assert body["providers_registered"] == 2
    assert body["message"] == "2 provider(s) registered"


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


def test_reports_both_providers_health(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """With no credentials configured, both providers degrade — never crash."""
    _use_registry(monkeypatch, _unconfigured_registry())

    body = client.get("/api/v1/exposure").json()
    assert body["providers"] == [
        {
            "name": "censys",
            "display_name": "Censys",
            "status": "degraded",
            "detail": "API credentials not configured",
        },
        {
            "name": "shodan",
            "display_name": "Shodan",
            "status": "degraded",
            "detail": "API key not configured",
        },
    ]


def test_value_param_runs_a_real_lookup_and_returns_a_merged_summary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _use_registry(monkeypatch, _unconfigured_registry())

    res = client.get("/api/v1/exposure", params={"value": "8.8.8.8"})
    assert res.status_code == 200
    body = res.json()
    summary = body["summary"]
    assert summary is not None
    assert summary["entity_type"] == "ipv4"
    assert summary["entity_value"] == "8.8.8.8"
    # Both providers contribute a finding, in deterministic order — merged
    # through the unmodified ExposureService/merge_findings code path.
    assert [f["provider"] for f in summary["findings"]] == ["censys", "shodan"]
    # No credentials configured: structured auth failures, never a crash or
    # a real request.
    assert all(f["status"] == "unauthorized" for f in summary["findings"])


def test_blank_value_param_is_treated_as_absent() -> None:
    res = client.get("/api/v1/exposure", params={"value": "   "})
    assert res.status_code == 200
    assert res.json()["summary"] is None


def test_disabled_registry_yields_a_valid_empty_summary_not_an_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A registry with nothing routable must never fail the endpoint."""
    _use_registry(monkeypatch, ExposureRegistry())

    res = client.get("/api/v1/exposure", params={"value": "8.8.8.8"})
    assert res.status_code == 200
    body = res.json()
    assert body["providers_registered"] == 0
    assert body["providers"] == []
    assert body["summary"]["findings"] == []
    assert body["summary"]["statistics"]["providers_queried"] == 0
