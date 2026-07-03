"""API contract tests for the Detection Knowledge endpoints (offline)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from threatlens.api.app import app

from .corpus import IP, SCENARIOS

_BY_ID = {s.id: s.summary for s in SCENARIOS}
client = TestClient(app)


def _summary_json(scenario_id: str) -> dict:
    return _BY_ID[scenario_id].model_dump(mode="json")


def test_recommend_endpoint_returns_ranked_community_matches() -> None:
    res = client.post("/api/v1/detection-knowledge/recommend", json=_summary_json("ip_c2"))
    assert res.status_code == 200
    body = res.json()
    assert body["exact_count"] >= 1
    assert body["matches"]
    top = body["matches"][0]
    assert top["match_type"] == "exact"
    assert f"ipv4:{IP}" in top["shared_iocs"]
    # Provenance is present on the wire.
    assert top["rule"]["source"]["repository"]
    assert top["rule"]["license"]["spdx_id"]


def test_recommend_is_separate_from_generated_detections() -> None:
    # The community endpoint returns community rules; /detections returns generated
    # artifacts. They are different shapes and never merged.
    community = client.post(
        "/api/v1/detection-knowledge/recommend", json=_summary_json("ip_c2")
    ).json()
    generated = client.post("/api/v1/detections", json=_summary_json("ip_c2")).json()
    assert "matches" in community and "artifacts" not in community
    assert "artifacts" in generated and "matches" not in generated


def test_recommend_empty_investigation_is_ok() -> None:
    res = client.post("/api/v1/detection-knowledge/recommend", json=_summary_json("no_findings"))
    assert res.status_code == 200
    assert res.json()["matches"] == []


def test_search_endpoint_filters() -> None:
    res = client.get("/api/v1/detection-knowledge/search", params={"technique": "T1071"})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 7
    assert body["stats"]["total_rules"] == 18


def test_search_by_language_and_repository() -> None:
    res = client.get(
        "/api/v1/detection-knowledge/search",
        params={"language": "yara", "repository": "yara-rules"},
    )
    assert res.status_code == 200
    assert all(r["language"] == "yara" for r in res.json()["rules"])


def test_search_rejects_unknown_enum_value() -> None:
    res = client.get("/api/v1/detection-knowledge/search", params={"language": "cobol"})
    assert res.status_code == 422  # FastAPI enum validation


def test_restricted_content_is_withheld_over_the_api() -> None:
    res = client.get("/api/v1/detection-knowledge/search", params={"repository": "elastic"})
    rules = res.json()["rules"]
    assert rules and all(r["content"] is None for r in rules)
