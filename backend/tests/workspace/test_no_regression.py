"""Regression tests for Phase 8.0: the Investigation Workspace must not change
any existing engine, route, or response shape.

These are not workspace feature tests (see test_service.py/test_api.py for
those) — they exist specifically to make the "no engine/API changes" claim in
the Phase 8.0 readiness review a checked fact rather than an assertion. All
offline; real (non-mocked) providers, exactly like the pre-existing
``test_investigate_mitre_technique_real_providers`` in ``test_investigation.py``.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.correlation import CORRELATION_FRAMEWORK_VERSION
from threatlens.detection import DETECTION_ENGINE_VERSION
from threatlens.reasoning import ENGINE_VERSION


class TestExistingRoutesUnaffected:
    """Adding the workspace router must not remove or shadow an existing route.

    Uses the generated OpenAPI schema (``app.openapi()["paths"]``) rather than
    walking ``app.routes`` directly — the exact ``Route``/``APIRouter``
    wrapping is a FastAPI-internal, version-dependent representation; the
    OpenAPI schema is the stable, public statement of what the app exposes.
    """

    def test_every_pre_phase_8_route_still_registered(self) -> None:
        paths = app.openapi()["paths"]
        expected = {
            "/api/v1/detect",
            "/api/v1/investigate",
            "/api/v1/explain",
            "/api/v1/detections",
            "/api/v1/detection-knowledge/recommend",
            "/api/v1/exposure",
            "/api/v1/identity",
            "/api/v1/correlation",
        }
        assert expected.issubset(paths.keys())

    def test_workspace_routes_are_additive(self) -> None:
        paths = app.openapi()["paths"]
        assert "/api/v1/workspace" in paths
        assert "/api/v1/workspace/{investigation_id}" in paths
        # Every pre-existing operation is untouched: same HTTP methods as before.
        assert set(paths["/api/v1/investigate"].keys()) == {"post"}
        assert set(paths["/api/v1/correlation"].keys()) == {"get"}


class TestExistingEngineVersionsUnchanged:
    """A version bump would signal the engine itself changed; this phase adds no
    rule, model field, or scoring change to any engine."""

    def test_reasoning_engine_version_unchanged(self) -> None:
        assert ENGINE_VERSION == "1.0"

    def test_detection_engine_version_unchanged(self) -> None:
        assert DETECTION_ENGINE_VERSION == "1.0"

    def test_correlation_framework_version_unchanged(self) -> None:
        assert CORRELATION_FRAMEWORK_VERSION == "0.1.0"


class TestExistingApiBehaviorUnchanged:
    """Smoke-test each pre-existing subsystem endpoint still behaves as before,
    with the workspace router mounted alongside it."""

    def test_investigate_still_returns_full_shape(self) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/investigate", json={"query": "T1059"})
        assert res.status_code == 200
        body = res.json()
        assert {
            "investigation_id",
            "entity",
            "threat_intelligence",
            "knowledge",
            "investigation_summary",
        }.issubset(body.keys())

    def test_detect_unchanged(self) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/detect", json={"query": "8.8.8.8"})
        assert res.status_code == 200
        assert res.json()["entity"]["type"] == "ipv4"

    def test_correlation_status_probe_unchanged(self) -> None:
        client = TestClient(app)
        res = client.get("/api/v1/correlation")
        assert res.status_code == 200
        body = res.json()
        assert body["framework_version"] == CORRELATION_FRAMEWORK_VERSION
        assert body["rules_registered"] > 0

    def test_detections_endpoint_unchanged(self) -> None:
        client = TestClient(app)
        investigate_res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
        summary = investigate_res.json()["investigation_summary"]
        res = client.post("/api/v1/detections", json=summary)
        assert res.status_code == 200
        assert "artifacts" in res.json()

    def test_exposure_status_probe_unchanged(self) -> None:
        client = TestClient(app)
        res = client.get("/api/v1/exposure")
        assert res.status_code == 200
        assert "framework_version" in res.json()

    def test_identity_status_probe_unchanged(self) -> None:
        client = TestClient(app)
        res = client.get("/api/v1/identity")
        assert res.status_code == 200
        assert "framework_version" in res.json()

    def test_health_endpoint_unchanged(self) -> None:
        client = TestClient(app)
        res = client.get("/health")
        assert res.status_code == 200


class TestCorsAllowsWorkspaceMethods:
    """The workspace's PUT/DELETE endpoints must survive a cross-origin browser
    preflight, not just a same-origin TestClient call.

    Caught in manual browser verification: a separately-hosted frontend (the
    documented ``NEXT_PUBLIC_API_URL`` cross-origin configuration) sends a CORS
    preflight (``OPTIONS`` + ``Access-Control-Request-Method``) before every
    PUT/DELETE. The app's CORSMiddleware previously allowed only GET/POST, so
    the preflight for update/delete failed and the browser never sent the real
    request — a real bug, not just a same-origin blind spot in the API tests
    above (which never exercise the browser's preflight at all).
    """

    def _preflight(self, method: str) -> object:
        client = TestClient(app)
        return client.options(
            "/api/v1/workspace/00000000-0000-0000-0000-000000000000",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": method,
            },
        )

    def test_put_preflight_succeeds(self) -> None:
        res = self._preflight("PUT")
        assert res.status_code == 200
        assert "PUT" in res.headers["access-control-allow-methods"]

    def test_delete_preflight_succeeds(self) -> None:
        res = self._preflight("DELETE")
        assert res.status_code == 200
        assert "DELETE" in res.headers["access-control-allow-methods"]

    def test_post_preflight_still_succeeds(self) -> None:
        """Existing POST-based routes (e.g. /investigate) are unaffected."""
        client = TestClient(app)
        res = client.options(
            "/api/v1/investigate",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert res.status_code == 200
        assert "POST" in res.headers["access-control-allow-methods"]
