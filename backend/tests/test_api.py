"""Integration tests for the detection API.

These exercise the real FastAPI app over the real engine (no mocks): a
well-formed request returns the engine's ``Entity`` plus a fresh ``search_id``;
malformed input is rejected with ``422``; unclassifiable input is a valid
``200`` result, never an error.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app

client = TestClient(app)

_ENTITY_FIELDS = {
    "type",
    "value",
    "normalized_value",
    "confidence",
    "validation",
    "possible_matches",
    "routing",
}


@pytest.mark.parametrize(
    ("query", "expected_type"),
    [
        ("8.8.8.8", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("example.com", "domain"),
        ("https://example.com/path", "url"),
        ("user@example.com", "email"),
        ("CVE-2024-3094", "cve"),
        ("T1059.001", "mitre_technique"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ("APT28", "threat_actor"),
        ("emotet", "malware_family"),
    ],
)
def test_detect_success(query: str, expected_type: str) -> None:
    res = client.post("/api/v1/detect", json={"query": query})
    assert res.status_code == 200
    body = res.json()
    assert body["entity"]["type"] == expected_type
    assert body["entity"]["value"] == query
    # search_id is a well-formed UUID.
    UUID(body["search_id"])
    # The full Entity contract is preserved over the wire.
    assert set(body["entity"]) >= _ENTITY_FIELDS


def test_detect_refangs_defanged_input() -> None:
    res = client.post("/api/v1/detect", json={"query": "hxxp://evil[.]com/x"})
    assert res.status_code == 200
    body = res.json()
    assert body["entity"]["type"] == "url"
    assert body["entity"]["normalized_value"] == "http://evil.com/x"


def test_unknown_single_token_is_200() -> None:
    res = client.post("/api/v1/detect", json={"query": "zzqqxx"})
    assert res.status_code == 200
    assert res.json()["entity"]["type"] == "unknown"


def test_freetext_is_200() -> None:
    res = client.post("/api/v1/detect", json={"query": "the quick brown fox"})
    assert res.status_code == 200
    assert res.json()["entity"]["type"] == "freetext"


@pytest.mark.parametrize(
    "payload",
    [
        {},  # missing field
        {"query": ""},  # empty
        {"query": "   "},  # whitespace only
        {"wrong": "x"},  # wrong field
        {"query": 123},  # wrong type
    ],
)
def test_invalid_requests_are_422(payload: dict[str, object]) -> None:
    res = client.post("/api/v1/detect", json=payload)
    assert res.status_code == 422


def test_oversized_query_is_422() -> None:
    res = client.post("/api/v1/detect", json={"query": "a" * 5000})
    assert res.status_code == 422


def test_search_ids_are_unique_per_request() -> None:
    a = client.post("/api/v1/detect", json={"query": "8.8.8.8"}).json()["search_id"]
    b = client.post("/api/v1/detect", json={"query": "8.8.8.8"}).json()["search_id"]
    assert a != b


def test_health() -> None:
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    # The liveness probe stays backward-compatible (status == "ok") while the
    # richer operational fields are covered in tests/test_health.py.
    assert res.json()["status"] == "ok"
