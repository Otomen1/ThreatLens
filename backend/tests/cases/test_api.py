"""Tests for the Case Management REST API (Phase 9.0).

Covers: create (201), get (200/404/422), list (with every filter), update
(200/404/409/422), delete (204/404), link/unlink a Workspace investigation
(200/404), and append a note (201/404/422). All offline — both the case and
workspace services are overridden per-test with ``LocalFileStorage`` rooted
at separate ``tmp_path`` subdirectories, mirroring
``tests/reporting/test_api.py``'s multi-service override fixture.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.cases import get_case_service
from threatlens.api.routes.workspace import get_workspace_service
from threatlens.cases import CaseService, LocalFileStorage
from threatlens.workspace import LocalFileStorage as WorkspaceLocalFileStorage
from threatlens.workspace import WorkspaceService


@pytest.fixture()
def client(tmp_path: Path):
    workspace_service = WorkspaceService(WorkspaceLocalFileStorage(tmp_path / "workspace"))
    case_service = CaseService(LocalFileStorage(tmp_path / "cases"), workspace_service)
    app.dependency_overrides[get_workspace_service] = lambda: workspace_service
    app.dependency_overrides[get_case_service] = lambda: case_service
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)
    app.dependency_overrides.pop(get_case_service, None)


def _create(client: TestClient, **overrides: object) -> dict:
    body: dict[str, object] = {"title": "Test case"}
    body.update(overrides)
    res = client.post("/api/v1/cases", json=body)
    assert res.status_code == 201, res.text
    return res.json()


def _save_investigation(client: TestClient, **overrides: object) -> dict:
    body: dict[str, object] = {"title": "Linked investigation", "investigation_type": "ipv4"}
    body.update(overrides)
    res = client.post("/api/v1/workspace", json=body)
    assert res.status_code == 201, res.text
    return res.json()


class TestCreateCase:
    def test_returns_201(self, client: TestClient) -> None:
        res = client.post("/api/v1/cases", json={"title": "Case"})
        assert res.status_code == 201

    def test_response_shape(self, client: TestClient) -> None:
        body = _create(client)
        assert UUID(body["id"])
        assert body["title"] == "Test case"
        assert body["status"] == "open"
        assert body["priority"] == "medium"
        assert body["tags"] == []
        assert body["linked_workspace_ids"] == []
        assert body["notes"] == []
        assert body["metadata"] == {}
        assert "created_at" in body
        assert "updated_at" in body

    def test_accepts_full_metadata(self, client: TestClient) -> None:
        body = _create(
            client,
            description="A phishing case",
            status="in_progress",
            priority="high",
            owner="alice",
            tags=["phishing", "urgent"],
            metadata={"source": "helpdesk"},
        )
        assert body["description"] == "A phishing case"
        assert body["status"] == "in_progress"
        assert body["priority"] == "high"
        assert body["owner"] == "alice"
        assert body["tags"] == ["phishing", "urgent"]
        assert body["metadata"] == {"source": "helpdesk"}

    def test_blank_title_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/cases", json={"title": ""})
        assert res.status_code == 422

    def test_missing_title_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/cases", json={})
        assert res.status_code == 422

    def test_invalid_priority_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/cases", json={"title": "Case", "priority": "urgent"})
        assert res.status_code == 422


class TestGetCase:
    def test_returns_200_for_existing_case(self, client: TestClient) -> None:
        created = _create(client)
        res = client.get(f"/api/v1/cases/{created['id']}")
        assert res.status_code == 200
        assert res.json() == created

    def test_returns_404_for_missing_case(self, client: TestClient) -> None:
        res = client.get(f"/api/v1/cases/{uuid4()}")
        assert res.status_code == 404

    def test_returns_422_for_malformed_id(self, client: TestClient) -> None:
        res = client.get("/api/v1/cases/not-a-uuid")
        assert res.status_code == 422


class TestListCases:
    def test_empty(self, client: TestClient) -> None:
        res = client.get("/api/v1/cases")
        assert res.status_code == 200
        assert res.json() == {"cases": [], "total": 0}

    def test_returns_every_case(self, client: TestClient) -> None:
        _create(client, title="A")
        _create(client, title="B")
        res = client.get("/api/v1/cases")
        assert res.json()["total"] == 2

    def test_filter_by_status(self, client: TestClient) -> None:
        _create(client, title="A", status="open")
        _create(client, title="B", status="closed")
        res = client.get("/api/v1/cases", params={"status": "closed"})
        assert [c["title"] for c in res.json()["cases"]] == ["B"]

    def test_filter_by_priority(self, client: TestClient) -> None:
        _create(client, title="A", priority="low")
        _create(client, title="B", priority="critical")
        res = client.get("/api/v1/cases", params={"priority": "critical"})
        assert [c["title"] for c in res.json()["cases"]] == ["B"]

    def test_filter_by_tag(self, client: TestClient) -> None:
        _create(client, title="A", tags=["x"])
        _create(client, title="B", tags=["y"])
        res = client.get("/api/v1/cases", params={"tag": "y"})
        assert [c["title"] for c in res.json()["cases"]] == ["B"]

    def test_filter_by_owner(self, client: TestClient) -> None:
        _create(client, title="A", owner="alice")
        _create(client, title="B", owner="bob")
        res = client.get("/api/v1/cases", params={"owner": "bob"})
        assert [c["title"] for c in res.json()["cases"]] == ["B"]

    def test_filter_by_title_substring(self, client: TestClient) -> None:
        _create(client, title="Suspicious Login")
        _create(client, title="Malware Outbreak")
        res = client.get("/api/v1/cases", params={"title": "login"})
        assert [c["title"] for c in res.json()["cases"]] == ["Suspicious Login"]


class TestUpdateCase:
    def test_returns_200_and_changes_only_given_fields(self, client: TestClient) -> None:
        created = _create(client, owner="alice")
        res = client.patch(f"/api/v1/cases/{created['id']}", json={"title": "Renamed"})
        assert res.status_code == 200
        body = res.json()
        assert body["title"] == "Renamed"
        assert body["owner"] == "alice"

    def test_returns_404_for_missing_case(self, client: TestClient) -> None:
        res = client.patch(f"/api/v1/cases/{uuid4()}", json={"title": "x"})
        assert res.status_code == 404

    def test_valid_status_transition_returns_200(self, client: TestClient) -> None:
        created = _create(client)  # starts OPEN
        res = client.patch(f"/api/v1/cases/{created['id']}", json={"status": "in_progress"})
        assert res.status_code == 200
        assert res.json()["status"] == "in_progress"

    def test_invalid_status_transition_returns_409(self, client: TestClient) -> None:
        created = _create(client)  # starts OPEN
        res = client.patch(f"/api/v1/cases/{created['id']}", json={"status": "resolved"})
        assert res.status_code == 409

    def test_invalid_transition_leaves_case_unchanged(self, client: TestClient) -> None:
        created = _create(client)
        client.patch(f"/api/v1/cases/{created['id']}", json={"status": "resolved"})
        reloaded = client.get(f"/api/v1/cases/{created['id']}").json()
        assert reloaded["status"] == "open"

    def test_blank_title_422(self, client: TestClient) -> None:
        created = _create(client)
        res = client.patch(f"/api/v1/cases/{created['id']}", json={"title": ""})
        assert res.status_code == 422


class TestDeleteCase:
    def test_returns_204(self, client: TestClient) -> None:
        created = _create(client)
        res = client.delete(f"/api/v1/cases/{created['id']}")
        assert res.status_code == 204

    def test_returns_404_for_missing_case(self, client: TestClient) -> None:
        res = client.delete(f"/api/v1/cases/{uuid4()}")
        assert res.status_code == 404

    def test_case_is_gone_afterward(self, client: TestClient) -> None:
        created = _create(client)
        client.delete(f"/api/v1/cases/{created['id']}")
        assert client.get(f"/api/v1/cases/{created['id']}").status_code == 404


class TestLinkWorkspace:
    def test_returns_200_and_links(self, client: TestClient) -> None:
        case = _create(client)
        investigation = _save_investigation(client)
        res = client.post(
            f"/api/v1/cases/{case['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        assert res.status_code == 200
        assert res.json()["linked_workspace_ids"] == [investigation["id"]]

    def test_returns_404_for_missing_case(self, client: TestClient) -> None:
        investigation = _save_investigation(client)
        res = client.post(
            f"/api/v1/cases/{uuid4()}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        assert res.status_code == 404

    def test_returns_404_for_nonexistent_investigation(self, client: TestClient) -> None:
        case = _create(client)
        res = client.post(
            f"/api/v1/cases/{case['id']}/workspace",
            json={"workspace_id": str(uuid4())},
        )
        assert res.status_code == 404

    def test_never_mutates_the_linked_investigation(self, client: TestClient) -> None:
        case = _create(client)
        investigation = _save_investigation(client)
        client.post(
            f"/api/v1/cases/{case['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        reloaded = client.get(f"/api/v1/workspace/{investigation['id']}").json()
        assert reloaded == investigation


class TestUnlinkWorkspace:
    def test_returns_200_and_unlinks(self, client: TestClient) -> None:
        case = _create(client)
        investigation = _save_investigation(client)
        client.post(
            f"/api/v1/cases/{case['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        res = client.delete(f"/api/v1/cases/{case['id']}/workspace/{investigation['id']}")
        assert res.status_code == 200
        assert res.json()["linked_workspace_ids"] == []

    def test_returns_404_for_missing_case(self, client: TestClient) -> None:
        res = client.delete(f"/api/v1/cases/{uuid4()}/workspace/{uuid4()}")
        assert res.status_code == 404

    def test_unlinking_non_linked_id_is_a_no_op_200(self, client: TestClient) -> None:
        case = _create(client)
        res = client.delete(f"/api/v1/cases/{case['id']}/workspace/{uuid4()}")
        assert res.status_code == 200


class TestAddNote:
    def test_returns_201_and_appends(self, client: TestClient) -> None:
        case = _create(client)
        res = client.post(
            f"/api/v1/cases/{case['id']}/notes",
            json={"author": "analyst", "content": "Investigating further."},
        )
        assert res.status_code == 201
        notes = res.json()["notes"]
        assert len(notes) == 1
        assert notes[0]["author"] == "analyst"
        assert notes[0]["content"] == "Investigating further."
        assert "timestamp" in notes[0]

    def test_returns_404_for_missing_case(self, client: TestClient) -> None:
        res = client.post(
            f"/api/v1/cases/{uuid4()}/notes",
            json={"author": "analyst", "content": "x"},
        )
        assert res.status_code == 404

    def test_blank_content_422(self, client: TestClient) -> None:
        case = _create(client)
        res = client.post(
            f"/api/v1/cases/{case['id']}/notes",
            json={"author": "analyst", "content": ""},
        )
        assert res.status_code == 422

    def test_multiple_notes_preserve_order(self, client: TestClient) -> None:
        case = _create(client)
        client.post(f"/api/v1/cases/{case['id']}/notes", json={"author": "a", "content": "first"})
        res = client.post(
            f"/api/v1/cases/{case['id']}/notes", json={"author": "b", "content": "second"}
        )
        assert [n["content"] for n in res.json()["notes"]] == ["first", "second"]


class TestFullLifecycle:
    def test_create_link_note_transition_delete(self, client: TestClient) -> None:
        """One representative end-to-end walk through every endpoint."""
        investigation = _save_investigation(client)
        case = _create(client, title="Full lifecycle case")

        linked = client.post(
            f"/api/v1/cases/{case['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        ).json()
        assert linked["linked_workspace_ids"] == [investigation["id"]]

        noted = client.post(
            f"/api/v1/cases/{case['id']}/notes",
            json={"author": "analyst", "content": "Confirmed malicious."},
        ).json()
        assert len(noted["notes"]) == 1

        progressed = client.patch(
            f"/api/v1/cases/{case['id']}", json={"status": "in_progress", "priority": "high"}
        ).json()
        assert progressed["status"] == "in_progress"
        assert progressed["priority"] == "high"

        resolved = client.patch(f"/api/v1/cases/{case['id']}", json={"status": "resolved"}).json()
        assert resolved["status"] == "resolved"

        assert client.delete(f"/api/v1/cases/{case['id']}").status_code == 204
        assert client.get(f"/api/v1/cases/{case['id']}").status_code == 404
        # The linked investigation survives the case's deletion untouched.
        assert client.get(f"/api/v1/workspace/{investigation['id']}").status_code == 200
