"""Regression tests for Phase 8.2: the Evidence Relationship Graph Framework must
not change any existing engine, route, or response shape — including the
Investigation Workspace and Timeline routes it shares a router file with.

Mirrors ``tests/timeline/test_no_regression.py``'s approach exactly (same
rationale: use the generated OpenAPI schema rather than walking
``app.routes``, since the underlying FastAPI route representation is
version-dependent).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.correlation import CORRELATION_FRAMEWORK_VERSION
from threatlens.detection import DETECTION_ENGINE_VERSION
from threatlens.graph import GRAPH_ENGINE_VERSION, GRAPH_FRAMEWORK_VERSION
from threatlens.reasoning import ENGINE_VERSION
from threatlens.timeline import TIMELINE_ENGINE_VERSION, TIMELINE_FRAMEWORK_VERSION


class TestExistingRoutesUnaffected:
    def test_every_pre_phase_8_2_route_still_registered(self) -> None:
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
            "/api/v1/workspace",
            "/api/v1/workspace/{investigation_id}",
            "/api/v1/workspace/{investigation_id}/timeline",
        }
        assert expected.issubset(paths.keys())

    def test_workspace_operations_unchanged_by_the_new_graph_route(self) -> None:
        paths = app.openapi()["paths"]
        assert set(paths["/api/v1/workspace"].keys()) == {"get", "post"}
        assert set(paths["/api/v1/workspace/{investigation_id}"].keys()) == {
            "get",
            "put",
            "delete",
        }
        assert set(paths["/api/v1/workspace/{investigation_id}/timeline"].keys()) == {"get"}

    def test_graph_route_is_additive(self) -> None:
        paths = app.openapi()["paths"]
        assert "/api/v1/workspace/{investigation_id}/graph" in paths
        assert set(paths["/api/v1/workspace/{investigation_id}/graph"].keys()) == {"get"}


class TestExistingEngineVersionsUnchanged:
    def test_reasoning_engine_version_unchanged(self) -> None:
        assert ENGINE_VERSION == "1.0"

    def test_detection_engine_version_unchanged(self) -> None:
        assert DETECTION_ENGINE_VERSION == "1.0"

    def test_correlation_framework_version_unchanged(self) -> None:
        assert CORRELATION_FRAMEWORK_VERSION == "0.1.0"

    def test_timeline_versions_unchanged(self) -> None:
        assert TIMELINE_FRAMEWORK_VERSION == "1.0"
        assert TIMELINE_ENGINE_VERSION == "1.0"

    def test_graph_versions_are_new_but_stable(self) -> None:
        assert GRAPH_FRAMEWORK_VERSION == "1.0"
        assert GRAPH_ENGINE_VERSION == "1.0"


class TestExistingApiBehaviorUnchanged:
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

    def test_workspace_save_still_returns_full_record_shape(self) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/workspace", json={"title": "Case", "investigation_type": "ipv4"})
        assert res.status_code == 201
        body = res.json()
        assert "investigation_summary" in body
        assert "detection_package" in body
        assert "correlation_summary" in body
        client.delete(f"/api/v1/workspace/{body['id']}")  # leave no state behind

    def test_timeline_endpoint_still_works(self) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/workspace", json={"title": "Case", "investigation_type": "ipv4"})
        body = res.json()
        assert client.get(f"/api/v1/workspace/{body['id']}/timeline").status_code == 200
        client.delete(f"/api/v1/workspace/{body['id']}")

    def test_correlation_status_probe_unchanged(self) -> None:
        client = TestClient(app)
        res = client.get("/api/v1/correlation")
        assert res.status_code == 200
        assert res.json()["framework_version"] == CORRELATION_FRAMEWORK_VERSION

    def test_health_endpoint_unchanged(self) -> None:
        client = TestClient(app)
        assert client.get("/health").status_code == 200
