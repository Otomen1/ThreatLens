"""Public API contract verification for ``/investigate`` (Phase 3.15).

The investigation response is treated as a public, frozen API. These tests pin
its full nested shape — the ``investigation_summary`` object and every reasoning
sub-object (findings, confidence + factors, weighted evidence, recommendations,
rollup) — so that:

* **backwards compatibility** holds: a documented key is never removed or
  retyped (the assertions use subset checks, so *adding* fields stays legal);
* **additive evolution** is the only permitted change: new optional fields may
  appear without breaking clients;
* **schema stability** is observable: the generated OpenAPI document keeps the
  documented component schemas.

The tests are offline — ``T1059`` resolves to a MITRE technique answered from the
bundled ATT&CK dataset, producing findings and recommendations deterministically.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.reasoning.engine import ENGINE_VERSION

client = TestClient(app)


def _investigate(query: str) -> dict[str, Any]:
    response = client.post("/api/v1/investigate", json={"query": query})
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


# --------------------------------------------------------------------------- #
# Top-level response contract
# --------------------------------------------------------------------------- #


def test_investigate_top_level_contract() -> None:
    body = _investigate("T1059")
    assert {
        "investigation_id",
        "entity",
        "threat_intelligence",
        "knowledge",
        "investigation_summary",
    }.issubset(body)


def test_detect_top_level_contract() -> None:
    response = client.post("/api/v1/detect", json={"query": "8.8.8.8"})
    assert response.status_code == 200
    body = response.json()
    assert {"search_id", "entity"}.issubset(body)
    assert {"type", "value", "normalized_value", "confidence", "validation"}.issubset(
        body["entity"]
    )


def test_aggregated_result_contract() -> None:
    body = _investigate("T1059")
    for framework in ("threat_intelligence", "knowledge"):
        agg = body[framework]
        assert {
            "entity_type",
            "entity_value",
            "providers",
            "evidence",
            "relationships",
            "references",
            "tags",
            "metadata",
        }.issubset(agg)


# --------------------------------------------------------------------------- #
# investigation_summary contract
# --------------------------------------------------------------------------- #


def test_investigation_summary_contract() -> None:
    summary = _investigate("T1059")["investigation_summary"]
    assert {
        "entity_type",
        "entity_value",
        "posture",
        "overall_confidence",
        "categories",
        "findings",
        "recommendations",
        "engine_version",
        "generated_at",
    }.issubset(summary)

    # Stable scalar types (severity/posture serialize as ints; version as a string).
    assert isinstance(summary["posture"], int)
    assert isinstance(summary["categories"], list)
    assert summary["engine_version"] == ENGINE_VERSION
    assert isinstance(summary["engine_version"], str)


def test_confidence_contract() -> None:
    confidence = _investigate("T1059")["investigation_summary"]["overall_confidence"]
    assert {"score", "band", "contested", "factors"}.issubset(confidence)
    assert isinstance(confidence["score"], int)
    assert isinstance(confidence["band"], str)
    assert isinstance(confidence["contested"], bool)
    for factor in confidence["factors"]:
        assert {"name", "contribution", "detail"}.issubset(factor)


def test_finding_contract() -> None:
    findings = _investigate("T1059")["investigation_summary"]["findings"]
    assert findings, "T1059 must yield at least one finding"
    finding = findings[0]
    assert {
        "id",
        "title",
        "categories",
        "subject_type",
        "subject_value",
        "severity",
        "confidence",
        "priority",
        "evidence",
        "relationships",
        "sources",
        "rationale",
        "rule_ids",
        "recommendations",
    }.issubset(finding)
    assert finding["id"].startswith("fnd_")
    assert isinstance(finding["severity"], int)
    assert isinstance(finding["priority"], int)
    assert {"score", "band", "contested", "factors"}.issubset(finding["confidence"])


def test_weighted_evidence_contract() -> None:
    findings = _investigate("T1059")["investigation_summary"]["findings"]
    weighted = next((ev for f in findings for ev in f["evidence"]), None)
    assert weighted is not None, "expected at least one weighted evidence item"
    assert {"evidence", "weight", "polarity", "dimension"}.issubset(weighted)
    # The reasoning layer wraps the existing AttributedEvidence (never redefines it).
    assert {"evidence", "sources"}.issubset(weighted["evidence"])


def test_recommendation_contract() -> None:
    summary = _investigate("T1059")["investigation_summary"]
    assert summary["recommendations"], "T1059 must yield at least one recommendation"
    rec = summary["recommendations"][0]
    assert {
        "action",
        "category",
        "priority",
        "target_type",
        "target_value",
        "rationale",
        "rule_id",
        "finding_ids",
    }.issubset(rec)
    # Rollup recommendations carry provenance back to their findings.
    assert isinstance(rec["finding_ids"], list)
    assert rec["finding_ids"], "rollup recommendations must retain finding provenance"


def test_rollup_is_priority_ordered() -> None:
    """The documented ordering guarantee: rollup is non-decreasing by priority."""
    recs = _investigate("T1059")["investigation_summary"]["recommendations"]
    priorities = [r["priority"] for r in recs]
    assert priorities == sorted(priorities)


# --------------------------------------------------------------------------- #
# Schema stability
# --------------------------------------------------------------------------- #


def test_openapi_exposes_investigation_schema() -> None:
    schema = client.get("/openapi.json").json()
    components = schema["components"]["schemas"]
    assert "InvestigationResponse" in components
    assert "InvestigationSummary" in components
    # The reasoning sub-models are reachable from the public schema.
    for model in ("Finding", "Confidence", "Recommendation", "WeightedEvidence"):
        assert model in components, f"{model} missing from OpenAPI components"
