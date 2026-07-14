"""Tests for GET /api/v1/workspace/{id}/timeline (Phase 8.1).

Offline, using an isolated LocalFileStorage rooted at pytest's ``tmp_path`` —
exactly like ``tests/workspace/test_api.py``'s ``client`` fixture, since this
endpoint lives on the same router and shares the same workspace service.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.workspace import get_timeline_service, get_workspace_service
from threatlens.timeline import TimelineService
from threatlens.workspace import LocalFileStorage, WorkspaceService


@pytest.fixture()
def client(tmp_path: Path):
    workspace_service = WorkspaceService(LocalFileStorage(tmp_path))
    app.dependency_overrides[get_workspace_service] = lambda: workspace_service
    app.dependency_overrides[get_timeline_service] = lambda: TimelineService()
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)
    app.dependency_overrides.pop(get_timeline_service, None)


def _save(client: TestClient, **overrides: object) -> dict:
    body = {"title": "Test case", "investigation_type": "ipv4"}
    body.update(overrides)
    res = client.post("/api/v1/workspace", json=body)
    assert res.status_code == 201, res.text
    return res.json()


class TestGetInvestigationTimeline:
    def test_returns_200_for_existing_investigation(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.get(f"/api/v1/workspace/{saved['id']}/timeline")
        assert res.status_code == 200

    def test_returns_404_for_missing_investigation(self, client: TestClient) -> None:
        res = client.get(f"/api/v1/workspace/{uuid4()}/timeline")
        assert res.status_code == 404

    def test_returns_422_for_malformed_id(self, client: TestClient) -> None:
        res = client.get("/api/v1/workspace/not-a-uuid/timeline")
        assert res.status_code == 422

    def test_response_shape(self, client: TestClient) -> None:
        saved = _save(client)
        body = client.get(f"/api/v1/workspace/{saved['id']}/timeline").json()
        assert set(body.keys()) == {
            "investigation_id",
            "entity_type",
            "entity_value",
            "generated_at",
            "events",
        }
        assert body["investigation_id"] == saved["id"]

    def test_empty_timeline_when_no_investigation_summary_attached(
        self, client: TestClient
    ) -> None:
        saved = _save(client)
        body = client.get(f"/api/v1/workspace/{saved['id']}/timeline").json()
        assert body["events"] == []

    def test_derives_events_from_a_real_investigate_summary(self, client: TestClient) -> None:
        """Round-trips a real /investigate summary through save -> timeline.

        Whether this produces >0 events depends on whether the offline
        providers report any evidence with ``observed_at`` set — this test
        only asserts the endpoint succeeds and returns a well-formed,
        internally consistent response either way, never that a specific
        count of events exists (that would assert something about live
        provider payloads, not about this framework's own logic).
        """
        investigate_res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
        summary = investigate_res.json()["investigation_summary"]
        saved = _save(client, investigation_summary=summary)

        res = client.get(f"/api/v1/workspace/{saved['id']}/timeline")
        assert res.status_code == 200
        body = res.json()
        assert body["entity_type"] == "ipv4"
        assert body["entity_value"] == "1.1.1.1"
        assert isinstance(body["events"], list)

    def test_repeated_fetch_is_byte_identical(self, client: TestClient) -> None:
        saved = _save(client)
        first = client.get(f"/api/v1/workspace/{saved['id']}/timeline").json()
        second = client.get(f"/api/v1/workspace/{saved['id']}/timeline").json()
        assert first == second

    def test_never_mutates_the_saved_investigation(self, client: TestClient) -> None:
        saved = _save(client)
        client.get(f"/api/v1/workspace/{saved['id']}/timeline")
        reloaded = client.get(f"/api/v1/workspace/{saved['id']}").json()
        assert reloaded == saved

    def test_existing_workspace_crud_unaffected(self, client: TestClient) -> None:
        """Adding the timeline route must not disturb any other workspace endpoint."""
        saved = _save(client)
        assert client.get("/api/v1/workspace").json()["total"] == 1
        assert client.put(
            f"/api/v1/workspace/{saved['id']}", json={"status": "closed"}
        ).status_code == 200
        assert client.delete(f"/api/v1/workspace/{saved['id']}").status_code == 204
