"""Free-form IOC extraction and batch investigation API coverage."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.search import BatchIocLimitExceeded, detect, extract_iocs


def _values(text: str) -> list[str]:
    return [entity.normalized_value for entity in extract_iocs(text, detector=detect)]


def test_extracts_mixed_iocs_from_analyst_notes() -> None:
    assert _values(
        "IOC=8.8.8.8, domain found=evil[.]example; visit hxxps://bad[.]example/x. "
        "Contact=operator@evil.example and hash d41d8cd98f00b204e9800998ecf8427e"
    ) == [
        "8.8.8.8",
        "evil.example",
        "https://bad.example/x",
        "operator@evil.example",
        "d41d8cd98f00b204e9800998ecf8427e",
    ]


def test_extraction_deduplicates_and_preserves_order() -> None:
    assert _values("example.com, 1.1.1.1\nexample.com 1.1.1.1") == ["example.com", "1.1.1.1"]


def test_extraction_ignores_non_ioc_words() -> None:
    assert _values("analyst says this is suspicious but has no indicators") == []


def test_extraction_enforces_twenty_ioc_limit() -> None:
    values = " ".join(f"198.51.100.{number}" for number in range(1, 22))
    with pytest.raises(BatchIocLimitExceeded):
        extract_iocs(values, detector=detect)


def test_batch_api_returns_grouped_results() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/investigate/batch", json={"query": "IOC=1.1.1.1, domain=example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert [item["entity"]["normalized_value"] for item in body["items"]] == ["1.1.1.1", "example.com"]
    assert all(item["status"] in {"completed", "failed"} for item in body["items"])


def test_batch_api_rejects_text_without_iocs() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/investigate/batch", json={"query": "nothing useful here"})
    assert response.status_code == 422
    assert "No supported IOC" in response.json()["detail"]
