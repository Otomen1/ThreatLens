"""Regression tests for Phase 9.1: Intelligence Collections must not change
any existing engine, route, or response shape — including Workspace and
Case Management, the two subsystems it links to.

Mirrors ``tests/cases/test_no_regression.py``'s approach exactly.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.cases import CASE_FRAMEWORK_VERSION
from threatlens.collections import COLLECTION_FRAMEWORK_VERSION
from threatlens.correlation import CORRELATION_FRAMEWORK_VERSION
from threatlens.detection import DETECTION_ENGINE_VERSION
from threatlens.graph import GRAPH_ENGINE_VERSION, GRAPH_FRAMEWORK_VERSION
from threatlens.reasoning import ENGINE_VERSION
from threatlens.reporting import REPORTING_FRAMEWORK_VERSION
from threatlens.timeline import TIMELINE_ENGINE_VERSION, TIMELINE_FRAMEWORK_VERSION
from threatlens.workspace import WORKSPACE_FRAMEWORK_VERSION


class TestExistingRoutesUnaffected:
    def test_every_pre_phase_9_1_route_still_registered(self) -> None:
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
            "/api/v1/workspace/{investigation_id}/graph",
            "/api/v1/workspace/{investigation_id}/export",
            "/api/v1/cases",
            "/api/v1/cases/{case_id}",
            "/api/v1/cases/{case_id}/workspace",
            "/api/v1/cases/{case_id}/workspace/{workspace_id}",
            "/api/v1/cases/{case_id}/notes",
        }
        assert expected.issubset(paths.keys())

    def test_workspace_and_case_operations_unchanged(self) -> None:
        paths = app.openapi()["paths"]
        assert set(paths["/api/v1/workspace"].keys()) == {"get", "post"}
        assert set(paths["/api/v1/workspace/{investigation_id}"].keys()) == {
            "get",
            "put",
            "delete",
        }
        assert set(paths["/api/v1/cases"].keys()) == {"get", "post"}
        assert set(paths["/api/v1/cases/{case_id}"].keys()) == {"get", "patch", "delete"}

    def test_collection_routes_are_additive(self) -> None:
        paths = app.openapi()["paths"]
        assert "/api/v1/collections" in paths
        assert "/api/v1/collections/search" in paths
        assert "/api/v1/collections/{collection_id}" in paths
        assert "/api/v1/collections/{collection_id}/indicator" in paths
        assert "/api/v1/collections/{collection_id}/workspace" in paths
        assert "/api/v1/collections/{collection_id}/case" in paths
        assert set(paths["/api/v1/collections"].keys()) == {"get", "post"}
        assert set(paths["/api/v1/collections/search"].keys()) == {"get"}
        assert set(paths["/api/v1/collections/{collection_id}"].keys()) == {
            "get",
            "patch",
            "delete",
        }
        assert set(paths["/api/v1/collections/{collection_id}/indicator"].keys()) == {
            "post",
            "delete",
        }


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

    def test_graph_versions_unchanged(self) -> None:
        assert GRAPH_FRAMEWORK_VERSION == "1.0"
        assert GRAPH_ENGINE_VERSION == "1.0"

    def test_reporting_version_unchanged(self) -> None:
        assert REPORTING_FRAMEWORK_VERSION == "1.0"

    def test_workspace_version_unchanged(self) -> None:
        assert WORKSPACE_FRAMEWORK_VERSION == "1.0"

    def test_case_version_unchanged(self) -> None:
        assert CASE_FRAMEWORK_VERSION == "1.0"

    def test_collection_version_is_new_but_stable(self) -> None:
        assert COLLECTION_FRAMEWORK_VERSION == "1.0"


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
        client.delete(f"/api/v1/workspace/{body['id']}")

    def test_cases_endpoint_still_works_alongside_workspace(self) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/cases", json={"title": "Case"})
        assert res.status_code == 201
        case_id = res.json()["id"]
        assert client.get(f"/api/v1/cases/{case_id}").status_code == 200
        client.delete(f"/api/v1/cases/{case_id}")

    def test_collections_endpoint_works_alongside_workspace_and_cases(self) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/collections", json={"name": "Collection"})
        assert res.status_code == 201
        collection_id = res.json()["id"]
        assert client.get(f"/api/v1/collections/{collection_id}").status_code == 200
        client.delete(f"/api/v1/collections/{collection_id}")

    def test_correlation_status_probe_unchanged(self) -> None:
        client = TestClient(app)
        res = client.get("/api/v1/correlation")
        assert res.status_code == 200
        assert res.json()["framework_version"] == CORRELATION_FRAMEWORK_VERSION

    def test_health_endpoint_unchanged(self) -> None:
        client = TestClient(app)
        assert client.get("/health").status_code == 200


class TestCorsAllowsCollectionMethods:
    """Collections reuse only HTTP methods already allowed by CORS (GET,
    POST, PATCH, DELETE — no new method was added for this phase), but a
    cross-origin browser preflight against a *new path* is still worth
    proving directly rather than assumed from the allow-list alone."""

    def _preflight(self, path: str, method: str) -> object:
        client = TestClient(app)
        return client.options(
            path,
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": method,
            },
        )

    def test_patch_preflight_succeeds(self) -> None:
        res = self._preflight("/api/v1/collections/00000000-0000-0000-0000-000000000000", "PATCH")
        assert res.status_code == 200
        assert "PATCH" in res.headers["access-control-allow-methods"]

    def test_delete_preflight_succeeds_on_indicator_path(self) -> None:
        res = self._preflight(
            "/api/v1/collections/00000000-0000-0000-0000-000000000000/indicator", "DELETE"
        )
        assert res.status_code == 200
        assert "DELETE" in res.headers["access-control-allow-methods"]

    def test_existing_case_patch_preflight_still_succeeds(self) -> None:
        """Existing Case Management routes are unaffected by adding Collections."""
        res = self._preflight("/api/v1/cases/00000000-0000-0000-0000-000000000000", "PATCH")
        assert res.status_code == 200
        assert "PATCH" in res.headers["access-control-allow-methods"]

    def test_existing_workspace_put_preflight_still_succeeds(self) -> None:
        """Existing Workspace routes are unaffected by adding Collections."""
        res = self._preflight("/api/v1/workspace/00000000-0000-0000-0000-000000000000", "PUT")
        assert res.status_code == 200
        assert "PUT" in res.headers["access-control-allow-methods"]
