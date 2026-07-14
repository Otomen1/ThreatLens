"""Tests for the Investigation Workspace REST API (Phase 8.0).

Covers: save (201), get (200/404), update (200/404), delete (204/404), list
(with every filter), validation errors (422), and that saved
investigation/detection/correlation payloads round-trip byte-for-byte through
the API. All offline — the workspace service is overridden per-test with a
LocalFileStorage rooted at pytest's ``tmp_path``, exactly like
``test_investigation.py``'s ``client_with_mock_service`` overrides
``get_investigation_service``.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.workspace import get_workspace_service
from threatlens.workspace import LocalFileStorage, WorkspaceService


@pytest.fixture()
def client(tmp_path: Path):
    """TestClient with a clean, isolated workspace service injected."""
    service = WorkspaceService(LocalFileStorage(tmp_path))
    app.dependency_overrides[get_workspace_service] = lambda: service
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)


def _save(client: TestClient, **overrides: object) -> dict:
    body = {"title": "Test case", "investigation_type": "ipv4"}
    body.update(overrides)
    res = client.post("/api/v1/workspace", json=body)
    assert res.status_code == 201, res.text
    return res.json()


# --------------------------------------------------------------------------- #
# POST /api/v1/workspace
# --------------------------------------------------------------------------- #


class TestSaveInvestigation:
    def test_returns_201(self, client: TestClient) -> None:
        res = client.post(
            "/api/v1/workspace", json={"title": "Case", "investigation_type": "ipv4"}
        )
        assert res.status_code == 201

    def test_response_shape(self, client: TestClient) -> None:
        body = _save(client)
        assert UUID(body["id"])
        assert body["title"] == "Test case"
        assert body["status"] == "open"
        assert body["tags"] == []
        assert body["investigation_type"] == "ipv4"
        assert "created_at" in body
        assert "updated_at" in body

    def test_accepts_full_metadata(self, client: TestClient) -> None:
        body = _save(
            client,
            status="in_progress",
            tags=["ioc", "urgent"],
            summary="Analyst note",
            severity=3,
        )
        assert body["status"] == "in_progress"
        assert body["tags"] == ["ioc", "urgent"]
        assert body["summary"] == "Analyst note"
        assert body["severity"] == 3

    def test_blank_title_422(self, client: TestClient) -> None:
        res = client.post(
            "/api/v1/workspace", json={"title": "", "investigation_type": "ipv4"}
        )
        assert res.status_code == 422

    def test_missing_investigation_type_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/workspace", json={"title": "Case"})
        assert res.status_code == 422

    def test_invalid_investigation_type_422(self, client: TestClient) -> None:
        res = client.post(
            "/api/v1/workspace", json={"title": "Case", "investigation_type": "not_a_type"}
        )
        assert res.status_code == 422

    def test_each_save_gets_a_distinct_id(self, client: TestClient) -> None:
        a = _save(client)
        b = _save(client)
        assert a["id"] != b["id"]

    def test_attaches_investigation_summary_verbatim(self, client: TestClient) -> None:
        """A real /investigate summary, saved then loaded, round-trips byte-for-byte."""
        investigate_res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
        summary = investigate_res.json()["investigation_summary"]

        saved = _save(client, investigation_type="ipv4", investigation_summary=summary)
        assert saved["investigation_summary"] == summary

        loaded = client.get(f"/api/v1/workspace/{saved['id']}").json()
        assert loaded["investigation_summary"] == summary


# --------------------------------------------------------------------------- #
# GET /api/v1/workspace/{id}
# --------------------------------------------------------------------------- #


class TestGetInvestigation:
    def test_returns_200_for_existing(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.get(f"/api/v1/workspace/{saved['id']}")
        assert res.status_code == 200
        assert res.json()["id"] == saved["id"]

    def test_returns_404_for_missing(self, client: TestClient) -> None:
        res = client.get(f"/api/v1/workspace/{uuid4()}")
        assert res.status_code == 404

    def test_returns_422_for_malformed_id(self, client: TestClient) -> None:
        res = client.get("/api/v1/workspace/not-a-uuid")
        assert res.status_code == 422


# --------------------------------------------------------------------------- #
# PUT /api/v1/workspace/{id}
# --------------------------------------------------------------------------- #


class TestUpdateInvestigation:
    def test_returns_200_and_applies_change(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.put(f"/api/v1/workspace/{saved['id']}", json={"status": "closed"})
        assert res.status_code == 200
        assert res.json()["status"] == "closed"

    def test_leaves_unset_fields_unchanged(self, client: TestClient) -> None:
        saved = _save(client, tags=["keep-me"])
        res = client.put(f"/api/v1/workspace/{saved['id']}", json={"status": "closed"})
        assert res.json()["tags"] == ["keep-me"]

    def test_bumps_updated_at(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.put(f"/api/v1/workspace/{saved['id']}", json={"status": "closed"})
        assert res.json()["updated_at"] >= saved["updated_at"]
        assert res.json()["created_at"] == saved["created_at"]

    def test_returns_404_for_missing(self, client: TestClient) -> None:
        res = client.put(f"/api/v1/workspace/{uuid4()}", json={"status": "closed"})
        assert res.status_code == 404

    def test_empty_body_is_a_no_op(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.put(f"/api/v1/workspace/{saved['id']}", json={})
        assert res.status_code == 200
        assert res.json()["title"] == saved["title"]
        assert res.json()["status"] == saved["status"]


# --------------------------------------------------------------------------- #
# DELETE /api/v1/workspace/{id}
# --------------------------------------------------------------------------- #


class TestDeleteInvestigation:
    def test_returns_204(self, client: TestClient) -> None:
        saved = _save(client)
        res = client.delete(f"/api/v1/workspace/{saved['id']}")
        assert res.status_code == 204

    def test_deleted_investigation_then_404s(self, client: TestClient) -> None:
        saved = _save(client)
        client.delete(f"/api/v1/workspace/{saved['id']}")
        assert client.get(f"/api/v1/workspace/{saved['id']}").status_code == 404

    def test_returns_404_for_missing(self, client: TestClient) -> None:
        res = client.delete(f"/api/v1/workspace/{uuid4()}")
        assert res.status_code == 404

    def test_double_delete_404s(self, client: TestClient) -> None:
        saved = _save(client)
        client.delete(f"/api/v1/workspace/{saved['id']}")
        res = client.delete(f"/api/v1/workspace/{saved['id']}")
        assert res.status_code == 404


# --------------------------------------------------------------------------- #
# GET /api/v1/workspace
# --------------------------------------------------------------------------- #


class TestListInvestigations:
    def test_empty_workspace(self, client: TestClient) -> None:
        res = client.get("/api/v1/workspace")
        assert res.status_code == 200
        body = res.json()
        assert body == {"investigations": [], "total": 0}

    def test_lists_saved_investigations(self, client: TestClient) -> None:
        _save(client, title="A")
        _save(client, title="B")
        body = client.get("/api/v1/workspace").json()
        assert body["total"] == 2
        assert len(body["investigations"]) == 2

    def test_list_items_are_metadata_only(self, client: TestClient) -> None:
        """The list projection excludes nested engine-output payloads."""
        investigate_res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
        summary = investigate_res.json()["investigation_summary"]
        _save(client, investigation_summary=summary)

        item = client.get("/api/v1/workspace").json()["investigations"][0]
        assert "investigation_summary" not in item
        assert "detection_package" not in item
        assert "correlation_summary" not in item
        assert set(item.keys()) == {
            "id",
            "title",
            "created_at",
            "updated_at",
            "status",
            "tags",
            "summary",
            "severity",
            "investigation_type",
        }

    def test_filter_by_status(self, client: TestClient) -> None:
        _save(client, title="Open")
        _save(client, title="Closed", status="closed")
        body = client.get("/api/v1/workspace", params={"status": "closed"}).json()
        assert body["total"] == 1
        assert body["investigations"][0]["title"] == "Closed"

    def test_filter_by_severity(self, client: TestClient) -> None:
        _save(client, title="Low", severity=1)
        _save(client, title="Critical", severity=4)
        body = client.get("/api/v1/workspace", params={"severity": 4}).json()
        assert body["total"] == 1
        assert body["investigations"][0]["title"] == "Critical"

    def test_filter_by_investigation_type(self, client: TestClient) -> None:
        _save(client, title="IP", investigation_type="ipv4")
        _save(client, title="Domain", investigation_type="domain")
        body = client.get("/api/v1/workspace", params={"investigation_type": "domain"}).json()
        assert body["total"] == 1
        assert body["investigations"][0]["title"] == "Domain"

    def test_filter_by_tag(self, client: TestClient) -> None:
        _save(client, title="Tagged", tags=["urgent"])
        _save(client, title="Untagged")
        body = client.get("/api/v1/workspace", params={"tag": "urgent"}).json()
        assert body["total"] == 1
        assert body["investigations"][0]["title"] == "Tagged"

    def test_search_query(self, client: TestClient) -> None:
        _save(client, title="Suspicious beacon activity")
        _save(client, title="Routine scan")
        body = client.get("/api/v1/workspace", params={"q": "beacon"}).json()
        assert body["total"] == 1
        assert body["investigations"][0]["title"] == "Suspicious beacon activity"

    def test_most_recently_updated_first(self, client: TestClient) -> None:
        first = _save(client, title="First")
        second = _save(client, title="Second")

        # B was created after A, so it sorts first.
        body = client.get("/api/v1/workspace").json()
        assert [item["id"] for item in body["investigations"]] == [second["id"], first["id"]]

        # Touching A bumps it back to the front.
        client.put(f"/api/v1/workspace/{first['id']}", json={"summary": "bumped"})
        body = client.get("/api/v1/workspace").json()
        assert [item["id"] for item in body["investigations"]] == [first["id"], second["id"]]
