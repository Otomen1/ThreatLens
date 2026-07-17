"""Tests for the Intelligence Collections REST API (Phase 9.1).

Covers: create (201), get (200/404/422), list (200), search (200, every
filter, and specifically the route-ordering hazard where a naively-registered
``/collections/{collection_id}`` route would shadow ``/collections/search``),
update (200/404/422), delete (204/404), add/remove indicator (201/200/404),
link Workspace/Case (200/404). All offline — the collection, workspace, and
case services are each overridden per-test with ``LocalFileStorage`` rooted
at separate ``tmp_path`` subdirectories, mirroring
``tests/cases/test_api.py``'s multi-service override fixture.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.cases import get_case_service
from threatlens.api.routes.collections import get_collection_service
from threatlens.api.routes.workspace import get_workspace_service
from threatlens.cases import CaseService
from threatlens.cases import LocalFileStorage as CaseLocalFileStorage
from threatlens.collections import CollectionService, LocalFileStorage
from threatlens.workspace import LocalFileStorage as WorkspaceLocalFileStorage
from threatlens.workspace import WorkspaceService


@pytest.fixture()
def client(tmp_path: Path):
    workspace_service = WorkspaceService(WorkspaceLocalFileStorage(tmp_path / "workspace"))
    case_service = CaseService(CaseLocalFileStorage(tmp_path / "cases"), workspace_service)
    collection_service = CollectionService(
        LocalFileStorage(tmp_path / "collections"), workspace_service, case_service
    )
    app.dependency_overrides[get_workspace_service] = lambda: workspace_service
    app.dependency_overrides[get_case_service] = lambda: case_service
    app.dependency_overrides[get_collection_service] = lambda: collection_service
    yield TestClient(app)
    app.dependency_overrides.pop(get_workspace_service, None)
    app.dependency_overrides.pop(get_case_service, None)
    app.dependency_overrides.pop(get_collection_service, None)


def _create(client: TestClient, **overrides: object) -> dict:
    body: dict[str, object] = {"name": "Test collection"}
    body.update(overrides)
    res = client.post("/api/v1/collections", json=body)
    assert res.status_code == 201, res.text
    return res.json()


def _save_investigation(client: TestClient, **overrides: object) -> dict:
    body: dict[str, object] = {"title": "Linked investigation", "investigation_type": "ipv4"}
    body.update(overrides)
    res = client.post("/api/v1/workspace", json=body)
    assert res.status_code == 201, res.text
    return res.json()


def _create_case(client: TestClient, **overrides: object) -> dict:
    body: dict[str, object] = {"title": "Linked case"}
    body.update(overrides)
    res = client.post("/api/v1/cases", json=body)
    assert res.status_code == 201, res.text
    return res.json()


class TestCreateCollection:
    def test_returns_201(self, client: TestClient) -> None:
        res = client.post("/api/v1/collections", json={"name": "Collection"})
        assert res.status_code == 201

    def test_response_shape(self, client: TestClient) -> None:
        body = _create(client)
        assert UUID(body["id"])
        assert body["name"] == "Test collection"
        assert body["source"] == "manual"
        assert body["tags"] == []
        assert body["indicators"] == []
        assert body["linked_case_ids"] == []
        assert body["linked_workspace_ids"] == []
        assert body["metadata"] == {}
        assert "created_at" in body
        assert "updated_at" in body

    def test_accepts_full_metadata(self, client: TestClient) -> None:
        body = _create(
            client,
            description="Silver Fox campaign infrastructure",
            category="campaign",
            tags=["silver-fox", "loader"],
            source="workspace",
            metadata={"analyst": "alice"},
        )
        assert body["description"] == "Silver Fox campaign infrastructure"
        assert body["category"] == "campaign"
        assert body["tags"] == ["silver-fox", "loader"]
        assert body["source"] == "workspace"
        assert body["metadata"] == {"analyst": "alice"}

    def test_blank_name_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/collections", json={"name": ""})
        assert res.status_code == 422

    def test_missing_name_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/collections", json={})
        assert res.status_code == 422

    def test_invalid_source_422(self, client: TestClient) -> None:
        res = client.post("/api/v1/collections", json={"name": "X", "source": "automatic"})
        assert res.status_code == 422


class TestGetCollection:
    def test_returns_200_for_existing_collection(self, client: TestClient) -> None:
        created = _create(client)
        res = client.get(f"/api/v1/collections/{created['id']}")
        assert res.status_code == 200
        assert res.json() == created

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        res = client.get(f"/api/v1/collections/{uuid4()}")
        assert res.status_code == 404

    def test_returns_422_for_malformed_id(self, client: TestClient) -> None:
        res = client.get("/api/v1/collections/not-a-uuid")
        assert res.status_code == 422


class TestListCollections:
    def test_empty(self, client: TestClient) -> None:
        res = client.get("/api/v1/collections")
        assert res.status_code == 200
        assert res.json() == {"collections": [], "total": 0}

    def test_returns_every_collection(self, client: TestClient) -> None:
        _create(client, name="A")
        _create(client, name="B")
        res = client.get("/api/v1/collections")
        assert res.json()["total"] == 2

    def test_rows_are_slim_no_indicators_field_but_have_count(self, client: TestClient) -> None:
        created = _create(client)
        client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "evil.com"},
        )
        row = client.get("/api/v1/collections").json()["collections"][0]
        assert "indicators" not in row
        assert row["indicator_count"] == 1

    def test_is_unfiltered_ignores_query_params(self, client: TestClient) -> None:
        """The plain list endpoint has no filter surface — see
        ``GET /api/v1/collections/search`` for filtering."""
        _create(client, name="A")
        _create(client, name="B", category="never-matches-A")
        res = client.get("/api/v1/collections", params={"category": "nonexistent"})
        assert res.json()["total"] == 2


class TestSearchCollectionsRouteOrdering:
    """Guards against the exact FastAPI/Starlette hazard where a
    later-registered ``{collection_id}`` route would greedily capture the
    literal path segment "search" and fail UUID coercion (422) before this
    handler is ever reached."""

    def test_search_path_is_not_shadowed_by_id_route(self, client: TestClient) -> None:
        res = client.get("/api/v1/collections/search")
        assert res.status_code == 200
        assert res.json() == {"collections": [], "total": 0}

    def test_search_with_no_filters_returns_everything(self, client: TestClient) -> None:
        _create(client, name="A")
        _create(client, name="B")
        res = client.get("/api/v1/collections/search")
        assert res.json()["total"] == 2


class TestSearchCollectionsFilters:
    def test_filter_by_name_substring(self, client: TestClient) -> None:
        _create(client, name="Silver Fox Campaign")
        _create(client, name="APT29 Infrastructure")
        res = client.get("/api/v1/collections/search", params={"name": "fox"})
        assert [c["name"] for c in res.json()["collections"]] == ["Silver Fox Campaign"]

    def test_filter_by_category(self, client: TestClient) -> None:
        _create(client, name="A", category="campaign")
        _create(client, name="B", category="blocklist")
        res = client.get("/api/v1/collections/search", params={"category": "blocklist"})
        assert [c["name"] for c in res.json()["collections"]] == ["B"]

    def test_filter_by_indicator_type(self, client: TestClient) -> None:
        a = _create(client, name="A")
        _create(client, name="B")
        client.post(
            f"/api/v1/collections/{a['id']}/indicator", json={"type": "cve", "value": "CVE-2024-1"}
        )
        res = client.get("/api/v1/collections/search", params={"indicator_type": "cve"})
        assert [c["name"] for c in res.json()["collections"]] == ["A"]

    def test_filter_by_tag(self, client: TestClient) -> None:
        _create(client, name="A", tags=["x"])
        _create(client, name="B", tags=["y"])
        res = client.get("/api/v1/collections/search", params={"tag": "y"})
        assert [c["name"] for c in res.json()["collections"]] == ["B"]

    def test_filter_by_linked_case_id(self, client: TestClient) -> None:
        case = _create_case(client)
        a = _create(client, name="A")
        _create(client, name="B")
        client.post(f"/api/v1/collections/{a['id']}/case", json={"case_id": case["id"]})
        res = client.get("/api/v1/collections/search", params={"linked_case_id": case["id"]})
        assert [c["name"] for c in res.json()["collections"]] == ["A"]

    def test_filter_by_linked_workspace_id(self, client: TestClient) -> None:
        investigation = _save_investigation(client)
        a = _create(client, name="A")
        _create(client, name="B")
        client.post(
            f"/api/v1/collections/{a['id']}/workspace", json={"workspace_id": investigation["id"]}
        )
        res = client.get(
            "/api/v1/collections/search", params={"linked_workspace_id": investigation["id"]}
        )
        assert [c["name"] for c in res.json()["collections"]] == ["A"]


class TestUpdateCollection:
    def test_returns_200_and_changes_only_given_fields(self, client: TestClient) -> None:
        created = _create(client, category="campaign")
        res = client.patch(f"/api/v1/collections/{created['id']}", json={"name": "Renamed"})
        assert res.status_code == 200
        body = res.json()
        assert body["name"] == "Renamed"
        assert body["category"] == "campaign"

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        res = client.patch(f"/api/v1/collections/{uuid4()}", json={"name": "x"})
        assert res.status_code == 404

    def test_blank_name_422(self, client: TestClient) -> None:
        created = _create(client)
        res = client.patch(f"/api/v1/collections/{created['id']}", json={"name": ""})
        assert res.status_code == 422

    def test_source_is_not_updatable(self, client: TestClient) -> None:
        created = _create(client, source="manual")
        res = client.patch(f"/api/v1/collections/{created['id']}", json={"source": "case"})
        # `source` is not a recognized field on UpdateCollectionRequest, so
        # sending it is silently ignored by Pydantic, not rejected.
        assert res.status_code == 200
        assert res.json()["source"] == "manual"


class TestDeleteCollection:
    def test_returns_204(self, client: TestClient) -> None:
        created = _create(client)
        res = client.delete(f"/api/v1/collections/{created['id']}")
        assert res.status_code == 204

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        res = client.delete(f"/api/v1/collections/{uuid4()}")
        assert res.status_code == 404

    def test_collection_is_gone_afterward(self, client: TestClient) -> None:
        created = _create(client)
        client.delete(f"/api/v1/collections/{created['id']}")
        assert client.get(f"/api/v1/collections/{created['id']}").status_code == 404


class TestAddIndicator:
    def test_returns_201_and_appends(self, client: TestClient) -> None:
        created = _create(client)
        res = client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "ipv4", "value": "1.1.1.1", "confidence": 80, "tags": ["c2"]},
        )
        assert res.status_code == 201
        indicators = res.json()["indicators"]
        assert len(indicators) == 1
        assert indicators[0]["type"] == "ipv4"
        assert indicators[0]["value"] == "1.1.1.1"
        assert indicators[0]["confidence"] == 80

    def test_readding_same_identity_merges_not_duplicates(self, client: TestClient) -> None:
        created = _create(client)
        client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "Evil.COM", "tags": ["a"]},
        )
        res = client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "evil.com", "tags": ["b"]},
        )
        indicators = res.json()["indicators"]
        assert len(indicators) == 1
        assert set(indicators[0]["tags"]) == {"a", "b"}

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        res = client.post(
            f"/api/v1/collections/{uuid4()}/indicator", json={"type": "domain", "value": "evil.com"}
        )
        assert res.status_code == 404

    def test_blank_value_422(self, client: TestClient) -> None:
        created = _create(client)
        res = client.post(
            f"/api/v1/collections/{created['id']}/indicator", json={"type": "domain", "value": ""}
        )
        assert res.status_code == 422

    def test_invalid_type_422(self, client: TestClient) -> None:
        created = _create(client)
        res = client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "not-a-type", "value": "x"},
        )
        assert res.status_code == 422

    def test_confidence_out_of_range_422(self, client: TestClient) -> None:
        created = _create(client)
        res = client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "evil.com", "confidence": 150},
        )
        assert res.status_code == 422


class TestRemoveIndicator:
    def test_returns_200_and_removes(self, client: TestClient) -> None:
        created = _create(client)
        client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "evil.com"},
        )
        res = client.request(
            "DELETE",
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "evil.com"},
        )
        assert res.status_code == 200
        assert res.json()["indicators"] == []

    def test_matches_by_normalized_value(self, client: TestClient) -> None:
        created = _create(client)
        client.post(
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "Evil.COM"},
        )
        res = client.request(
            "DELETE",
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "evil.com"},
        )
        assert res.json()["indicators"] == []

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        res = client.request(
            "DELETE",
            f"/api/v1/collections/{uuid4()}/indicator",
            json={"type": "domain", "value": "evil.com"},
        )
        assert res.status_code == 404

    def test_removing_non_present_identity_is_a_no_op_200(self, client: TestClient) -> None:
        created = _create(client)
        res = client.request(
            "DELETE",
            f"/api/v1/collections/{created['id']}/indicator",
            json={"type": "domain", "value": "nope.com"},
        )
        assert res.status_code == 200


class TestLinkWorkspace:
    def test_returns_200_and_links(self, client: TestClient) -> None:
        collection = _create(client)
        investigation = _save_investigation(client)
        res = client.post(
            f"/api/v1/collections/{collection['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        assert res.status_code == 200
        assert res.json()["linked_workspace_ids"] == [investigation["id"]]

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        investigation = _save_investigation(client)
        res = client.post(
            f"/api/v1/collections/{uuid4()}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        assert res.status_code == 404

    def test_returns_404_for_nonexistent_investigation(self, client: TestClient) -> None:
        collection = _create(client)
        res = client.post(
            f"/api/v1/collections/{collection['id']}/workspace",
            json={"workspace_id": str(uuid4())},
        )
        assert res.status_code == 404

    def test_never_mutates_the_linked_investigation(self, client: TestClient) -> None:
        collection = _create(client)
        investigation = _save_investigation(client)
        client.post(
            f"/api/v1/collections/{collection['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        )
        reloaded = client.get(f"/api/v1/workspace/{investigation['id']}").json()
        assert reloaded == investigation


class TestLinkCase:
    def test_returns_200_and_links(self, client: TestClient) -> None:
        collection = _create(client)
        case = _create_case(client)
        res = client.post(
            f"/api/v1/collections/{collection['id']}/case", json={"case_id": case["id"]}
        )
        assert res.status_code == 200
        assert res.json()["linked_case_ids"] == [case["id"]]

    def test_returns_404_for_missing_collection(self, client: TestClient) -> None:
        case = _create_case(client)
        res = client.post(f"/api/v1/collections/{uuid4()}/case", json={"case_id": case["id"]})
        assert res.status_code == 404

    def test_returns_404_for_nonexistent_case(self, client: TestClient) -> None:
        collection = _create(client)
        res = client.post(
            f"/api/v1/collections/{collection['id']}/case", json={"case_id": str(uuid4())}
        )
        assert res.status_code == 404

    def test_never_mutates_the_linked_case(self, client: TestClient) -> None:
        collection = _create(client)
        case = _create_case(client)
        client.post(f"/api/v1/collections/{collection['id']}/case", json={"case_id": case["id"]})
        reloaded = client.get(f"/api/v1/cases/{case['id']}").json()
        assert reloaded == case


class TestFullLifecycle:
    def test_create_link_indicator_search_delete(self, client: TestClient) -> None:
        """One representative end-to-end walk through every endpoint."""
        investigation = _save_investigation(client)
        case = _create_case(client)
        collection = _create(client, name="Full lifecycle collection", category="campaign")

        linked_ws = client.post(
            f"/api/v1/collections/{collection['id']}/workspace",
            json={"workspace_id": investigation["id"]},
        ).json()
        assert linked_ws["linked_workspace_ids"] == [investigation["id"]]

        linked_case = client.post(
            f"/api/v1/collections/{collection['id']}/case", json={"case_id": case["id"]}
        ).json()
        assert linked_case["linked_case_ids"] == [case["id"]]

        with_indicator = client.post(
            f"/api/v1/collections/{collection['id']}/indicator",
            json={"type": "sha256", "value": "a" * 64, "confidence": 90},
        ).json()
        assert len(with_indicator["indicators"]) == 1

        found = client.get("/api/v1/collections/search", params={"indicator_type": "sha256"}).json()
        assert collection["id"] in [c["id"] for c in found["collections"]]

        renamed = client.patch(
            f"/api/v1/collections/{collection['id']}", json={"name": "Renamed collection"}
        ).json()
        assert renamed["name"] == "Renamed collection"

        without_indicator = client.request(
            "DELETE",
            f"/api/v1/collections/{collection['id']}/indicator",
            json={"type": "sha256", "value": "a" * 64},
        ).json()
        assert without_indicator["indicators"] == []

        assert client.delete(f"/api/v1/collections/{collection['id']}").status_code == 204
        assert client.get(f"/api/v1/collections/{collection['id']}").status_code == 404
        # The linked investigation and case survive the collection's deletion untouched.
        assert client.get(f"/api/v1/workspace/{investigation['id']}").status_code == 200
        assert client.get(f"/api/v1/cases/{case['id']}").status_code == 200
