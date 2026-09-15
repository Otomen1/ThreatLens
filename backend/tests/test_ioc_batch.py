"""Free-form IOC extraction and batch investigation API coverage."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.routes.investigation import get_investigation_service
from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.search import (
    BatchIocLimitExceeded,
    detect,
    extract_ioc_report,
    extract_iocs,
)


def _values(text: str) -> list[str]:
    return [entity.normalized_value for entity in extract_iocs(text, detector=detect)]


def test_extracts_mixed_iocs_from_analyst_notes() -> None:
    assert _values(
        "IOC=8.8.8.8, domain found=evil[.]com; visit hxxps://bad[.]com/x. "
        "Contact=operator@evil.com and hash d41d8cd98f00b204e9800998ecf8427e"
    ) == [
        "8.8.8.8",
        "evil.com",
        "https://bad.com/x",
        "operator@evil.com",
        "d41d8cd98f00b204e9800998ecf8427e",
    ]


def test_extraction_deduplicates_and_preserves_order() -> None:
    assert _values("example.com, 1.1.1.1\nexample.com 1.1.1.1") == ["example.com", "1.1.1.1"]


def test_extraction_report_counts_only_shaped_candidates() -> None:
    def detector(value: str) -> Entity:
        entity_type = EntityType.UNKNOWN if value == "999.999.999.999" else EntityType.DOMAIN
        return Entity(
            type=entity_type,
            value=value,
            normalized_value=value,
            confidence=100,
            validation=ValidationStatus.VALID,
        )

    report = extract_ioc_report(
        "ordinary prose example.com example.com 999.999.999.999",
        detector=detector,
    )
    assert [entity.normalized_value for entity in report.entities] == ["example.com"]
    assert report.duplicates == 1
    assert report.invalid == 1


def test_extraction_ignores_non_ioc_words() -> None:
    assert _values("analyst says this is suspicious but has no indicators") == []


def test_extraction_enforces_twenty_ioc_limit() -> None:
    values = " ".join(f"198.51.100.{number}" for number in range(1, 22))
    with pytest.raises(BatchIocLimitExceeded):
        extract_iocs(values, detector=detect)


def test_extraction_allows_exactly_twenty_iocs() -> None:
    values = " ".join(f"198.51.100.{number}" for number in range(1, 21))
    assert len(extract_iocs(values, detector=detect)) == 20


@pytest.mark.parametrize("query", ["CVE-2024-3094", "T1059.001", "rundll32.exe"])
def test_preview_preserves_structured_single_searches(query: str) -> None:
    response = TestClient(app).post(
        "/api/v1/investigate/batch/preview",
        json={"query": query},
    )
    assert response.status_code == 200
    assert response.json()["supported"] == 1


def test_preview_reports_counts_estimate_and_confirmation() -> None:
    response = TestClient(app).post(
        "/api/v1/investigate/batch/preview",
        json={"query": " ".join(f"198.51.100.{number}" for number in range(1, 7))},
    )
    body = response.json()
    assert response.status_code == 200
    assert body["supported"] == 6
    assert body["estimated_ti_requests"] >= 0
    assert body["requires_confirmation"] is True
    assert "quota" in body["quota_warning"].lower()


def test_batch_api_returns_grouped_results() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/v1/investigate/batch",
        json={"query": "IOC=1.1.1.1, domain=example.com"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert [item["entity"]["normalized_value"] for item in body["items"]] == [
        "1.1.1.1",
        "example.com",
    ]
    assert all(item["status"] in {"completed", "failed"} for item in body["items"])


def test_batch_api_rejects_text_without_iocs() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/investigate/batch", json={"query": "nothing useful here"})
    assert response.status_code == 422
    assert "No supported IOC" in response.json()["detail"]


def test_batch_api_sanitizes_internal_exceptions() -> None:
    class BrokenService:
        async def investigate(self, entity: Entity) -> None:
            raise RuntimeError("secret-token-and-provider-payload")

    app.dependency_overrides[get_investigation_service] = lambda: BrokenService()
    try:
        response = TestClient(app).post(
            "/api/v1/investigate/batch",
            json={"query": "1.1.1.1"},
        )
    finally:
        app.dependency_overrides.pop(get_investigation_service, None)
    item = response.json()["items"][0]
    assert response.status_code == 200
    assert item["status"] == "failed"
    assert item["error_code"] == "investigation_failed"
    assert item["retryable"] is True
    assert "secret-token" not in item["error"]
