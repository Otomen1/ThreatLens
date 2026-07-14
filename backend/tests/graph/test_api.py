"""Tests for GET /api/v1/workspace/{id}/graph (Phase 8.2).

Offline, using an isolated LocalFileStorage rooted at pytest's ``tmp_path`` —
exactly like ``tests/timeline/test_api.py``'s ``client`` fixture, since this
endpoint lives on the same router and shares the same workspace service.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.workspace import get_graph_service, get_workspace_service
from threatlens.graph import GraphService
from threatlens.workspace import LocalFileStorage, WorkspaceService


@pytest.fixture()
def client(tmp_path: Path):
    workspace_service = WorkspaceService(LocalFileStorage(tmp_path))
    app.dependency_overrides[get_workspace_service] = lambda: workspace_service
    app.dependency_overrides[get_graph_service] = lambda: GraphService()
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)
    app.dependency_overrides.pop(get_graph_service, None)


def _save(client: TestClient, **overrides: object) -> dict:
    body = {"title": "Test case", "investigation_type": "ipv4"}
    body.update(overrides)
    res = client.post("/api/v1/workspace", json=body)
    assert res.status_code == 201, res.text
    return res.json()


class TestGetInvestigationGraph:
    def test_returns_200_for_existing_investigation(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.get(f"/api/v1/workspace/{saved['id']}/graph")
        assert res.status_code == 200

    def test_returns_404_for_missing_investigation(self, client: TestClient) -> None:
        res = client.get(f"/api/v1/workspace/{uuid4()}/graph")
        assert res.status_code == 404

    def test_returns_422_for_malformed_id(self, client: TestClient) -> None:
        res = client.get("/api/v1/workspace/not-a-uuid/graph")
        assert res.status_code == 422

    def test_response_shape(self, client: TestClient) -> None:
        saved = _save(client)
        body = client.get(f"/api/v1/workspace/{saved['id']}/graph").json()
        assert set(body.keys()) == {
            "investigation_id",
            "entity_type",
            "entity_value",
            "generated_at",
            "nodes",
            "edges",
            "node_count",
            "edge_count",
            "graph_version",
        }
        assert body["investigation_id"] == saved["id"]

    def test_empty_graph_when_no_investigation_summary_attached(self, client: TestClient) -> None:
        saved = _save(client)
        body = client.get(f"/api/v1/workspace/{saved['id']}/graph").json()
        assert body["nodes"] == []
        assert body["edges"] == []
        assert body["node_count"] == 0
        assert body["edge_count"] == 0

    def test_derives_a_graph_from_a_real_investigate_summary(self, client: TestClient) -> None:
        """Round-trips a real /investigate summary through save -> graph.

        Whether this produces >0 nodes depends on whether the offline
        providers report any explicit relationships — this test only
        asserts the endpoint succeeds and returns a well-formed, internally
        consistent response either way, never a specific node/edge count
        (that would assert something about live provider payloads, not
        about this framework's own logic).
        """
        investigate_res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
        summary = investigate_res.json()["investigation_summary"]
        saved = _save(client, investigation_summary=summary)

        res = client.get(f"/api/v1/workspace/{saved['id']}/graph")
        assert res.status_code == 200
        body = res.json()
        assert body["entity_type"] == "ipv4"
        assert body["entity_value"] == "1.1.1.1"
        assert isinstance(body["nodes"], list)
        assert isinstance(body["edges"], list)
        assert body["node_count"] == len(body["nodes"])
        assert body["edge_count"] == len(body["edges"])

    def test_repeated_fetch_is_byte_identical(self, client: TestClient) -> None:
        saved = _save(client)
        first = client.get(f"/api/v1/workspace/{saved['id']}/graph").json()
        second = client.get(f"/api/v1/workspace/{saved['id']}/graph").json()
        assert first == second

    def test_never_mutates_the_saved_investigation(self, client: TestClient) -> None:
        saved = _save(client)
        client.get(f"/api/v1/workspace/{saved['id']}/graph")
        reloaded = client.get(f"/api/v1/workspace/{saved['id']}").json()
        assert reloaded == saved

    def test_existing_workspace_crud_unaffected(self, client: TestClient) -> None:
        """Adding the graph route must not disturb any other workspace endpoint."""
        saved = _save(client)
        assert client.get("/api/v1/workspace").json()["total"] == 1
        assert (
            client.put(f"/api/v1/workspace/{saved['id']}", json={"status": "closed"}).status_code
            == 200
        )
        assert client.delete(f"/api/v1/workspace/{saved['id']}").status_code == 204

    def test_timeline_route_still_works_alongside_graph(self, client: TestClient) -> None:
        """The graph route must not disturb the sibling timeline route."""
        saved = _save(client)
        assert client.get(f"/api/v1/workspace/{saved['id']}/timeline").status_code == 200
        assert client.get(f"/api/v1/workspace/{saved['id']}/graph").status_code == 200
