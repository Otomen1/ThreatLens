"""Tests for GET /api/v1/workspace/{id}/export (Phase 8.4).

Offline, using an isolated LocalFileStorage rooted at pytest's ``tmp_path`` —
exactly like ``tests/graph/test_api.py``'s and ``tests/timeline/test_api.py``'s
``client`` fixtures, since this endpoint lives on the same router and shares
the same workspace service.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.workspace import (
    get_graph_service,
    get_report_service,
    get_timeline_service,
    get_workspace_service,
)
from threatlens.graph import GraphService
from threatlens.reporting import REPORTING_FRAMEWORK_VERSION, ReportService
from threatlens.timeline import TimelineService
from threatlens.workspace import LocalFileStorage, WorkspaceService


@pytest.fixture()
def client(tmp_path: Path):
    workspace_service = WorkspaceService(LocalFileStorage(tmp_path))
    timeline_service = TimelineService()
    graph_service = GraphService()
    app.dependency_overrides[get_workspace_service] = lambda: workspace_service
    app.dependency_overrides[get_timeline_service] = lambda: timeline_service
    app.dependency_overrides[get_graph_service] = lambda: graph_service
    app.dependency_overrides[get_report_service] = lambda: ReportService(
        timeline_service, graph_service
    )
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)
    app.dependency_overrides.pop(get_timeline_service, None)
    app.dependency_overrides.pop(get_graph_service, None)
    app.dependency_overrides.pop(get_report_service, None)


def _save(client: TestClient, **overrides: object) -> dict:
    body = {"title": "Test case", "investigation_type": "ipv4"}
    body.update(overrides)
    res = client.post("/api/v1/workspace", json=body)
    assert res.status_code == 201, res.text
    return res.json()


class TestGetInvestigationReport:
    def test_returns_200_for_existing_investigation(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.get(f"/api/v1/workspace/{saved['id']}/export")
        assert res.status_code == 200

    def test_returns_404_for_missing_investigation(self, client: TestClient) -> None:
        res = client.get(f"/api/v1/workspace/{uuid4()}/export")
        assert res.status_code == 404

    def test_returns_422_for_malformed_id(self, client: TestClient) -> None:
        res = client.get("/api/v1/workspace/not-a-uuid/export")
        assert res.status_code == 422

    def test_response_shape(self, client: TestClient) -> None:
        saved = _save(client)
        body = client.get(f"/api/v1/workspace/{saved['id']}/export").json()
        assert set(body.keys()) == {"report_schema_version", "investigation", "timeline", "graph"}
        assert body["report_schema_version"] == REPORTING_FRAMEWORK_VERSION
        assert body["investigation"]["id"] == saved["id"]
        assert body["timeline"]["investigation_id"] == saved["id"]
        assert body["graph"]["investigation_id"] == saved["id"]

    def test_investigation_section_matches_the_plain_get(self, client: TestClient) -> None:
        saved = _save(client)
        exported = client.get(f"/api/v1/workspace/{saved['id']}/export").json()
        plain = client.get(f"/api/v1/workspace/{saved['id']}").json()
        assert exported["investigation"] == plain

    def test_timeline_section_matches_the_dedicated_timeline_route(
        self, client: TestClient
    ) -> None:
        saved = _save(client)
        exported = client.get(f"/api/v1/workspace/{saved['id']}/export").json()
        dedicated = client.get(f"/api/v1/workspace/{saved['id']}/timeline").json()
        assert exported["timeline"] == dedicated

    def test_graph_section_matches_the_dedicated_graph_route(self, client: TestClient) -> None:
        saved = _save(client)
        exported = client.get(f"/api/v1/workspace/{saved['id']}/export").json()
        dedicated = client.get(f"/api/v1/workspace/{saved['id']}/graph").json()
        assert exported["graph"] == dedicated

    def test_derives_a_report_from_a_real_investigate_summary(self, client: TestClient) -> None:
        investigate_res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
        inv_summary = investigate_res.json()["investigation_summary"]
        saved = _save(client, investigation_summary=inv_summary)

        res = client.get(f"/api/v1/workspace/{saved['id']}/export")
        assert res.status_code == 200
        body = res.json()
        assert body["investigation"]["investigation_summary"]["entity_type"] == "ipv4"
        assert isinstance(body["timeline"]["events"], list)
        assert isinstance(body["graph"]["nodes"], list)

    def test_repeated_fetch_is_byte_identical(self, client: TestClient) -> None:
        saved = _save(client)
        first = client.get(f"/api/v1/workspace/{saved['id']}/export").json()
        second = client.get(f"/api/v1/workspace/{saved['id']}/export").json()
        assert first == second

    def test_never_mutates_the_saved_investigation(self, client: TestClient) -> None:
        saved = _save(client)
        client.get(f"/api/v1/workspace/{saved['id']}/export")
        reloaded = client.get(f"/api/v1/workspace/{saved['id']}").json()
        assert reloaded == saved

    def test_sibling_timeline_and_graph_routes_still_work(self, client: TestClient) -> None:
        saved = _save(client)
        assert client.get(f"/api/v1/workspace/{saved['id']}/timeline").status_code == 200
        assert client.get(f"/api/v1/workspace/{saved['id']}/graph").status_code == 200
        assert client.get(f"/api/v1/workspace/{saved['id']}/export").status_code == 200

    def test_existing_workspace_crud_unaffected(self, client: TestClient) -> None:
        saved = _save(client)
        assert client.get("/api/v1/workspace").json()["total"] == 1
        assert (
            client.put(f"/api/v1/workspace/{saved['id']}", json={"status": "closed"}).status_code
            == 200
        )
        assert client.delete(f"/api/v1/workspace/{saved['id']}").status_code == 204
