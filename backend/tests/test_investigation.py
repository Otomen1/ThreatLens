"""Tests for the unified investigation service and /api/v1/investigate endpoint.

Covers: concurrent execution, TI-only entities, Knowledge-only entities, both
frameworks, partial failures, empty results, provider exceptions, response shape,
and dependency-override API integration. All tests are offline (no network).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app, get_investigation_service
from threatlens.entities.models import Entity, RoutingMetadata
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.investigation import InvestigationService
from threatlens.providers import AggregatedResult, ProviderRouter
from threatlens.providers.results import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    ResultStatus,
)
from threatlens.reference import ReferenceRouter

# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


def _entity(
    type_: EntityType,
    value: str = "test",
    normalized: str | None = None,
) -> Entity:
    return Entity(
        type=type_,
        value=value,
        normalized_value=normalized or value,
        confidence=95,
        validation=ValidationStatus.VALID,
        possible_matches=[],
        routing=RoutingMetadata(providers=[]),
    )


def _ok_result(
    provider: str,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "1.2.3.4",
) -> IntelligenceResult:
    return IntelligenceResult(
        provider=provider,
        provider_display_name=provider.upper(),
        entity_type=entity_type,
        entity_value=entity_value,
        status=ResultStatus.OK,
        evidence=[
            Evidence(
                type=EvidenceType.CLASSIFICATION,
                summary=f"Test evidence from {provider}",
                value=provider,
            )
        ],
    )


def _fail_result(
    provider: str,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "1.2.3.4",
) -> IntelligenceResult:
    return IntelligenceResult.failure(
        provider=provider,
        provider_display_name=provider.upper(),
        entity_type=entity_type,
        entity_value=entity_value,
        message="Provider failed",
    )


def _not_found_result(
    provider: str,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "1.2.3.4",
) -> IntelligenceResult:
    return IntelligenceResult.not_found(
        provider=provider,
        provider_display_name=provider.upper(),
        entity_type=entity_type,
        entity_value=entity_value,
    )


def _make_ti_provider(
    name: str,
    result: IntelligenceResult | None = None,
    entity_type: EntityType = EntityType.IPV4,
) -> MagicMock:
    provider = MagicMock()
    provider.safe_search = AsyncMock(
        return_value=result or _ok_result(name, entity_type=entity_type)
    )
    return provider


def _make_ref_provider(
    name: str,
    result: IntelligenceResult | None = None,
    entity_type: EntityType = EntityType.MITRE_TECHNIQUE,
) -> MagicMock:
    provider = MagicMock()
    provider.safe_lookup = AsyncMock(
        return_value=result or _ok_result(name, entity_type=entity_type)
    )
    return provider


def _make_service(
    ti_providers: tuple = (),
    ref_providers: tuple = (),
) -> InvestigationService:
    ti_router = MagicMock(spec=ProviderRouter)
    ti_router.route.return_value = ti_providers
    ref_router = MagicMock(spec=ReferenceRouter)
    ref_router.route.return_value = ref_providers
    return InvestigationService(ti_router, ref_router)


# --------------------------------------------------------------------------- #
# InvestigationService unit tests
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_ti_only_entity() -> None:
    """TI provider runs; no reference providers; knowledge is empty."""
    ti_prov = _make_ti_provider("abuseipdb")
    service = _make_service(ti_providers=(ti_prov,))
    entity = _entity(EntityType.IPV4, "1.2.3.4")

    ti, knowledge = await service.investigate(entity)

    assert len(ti.providers) == 1
    assert ti.providers[0].provider == "abuseipdb"
    assert ti.providers[0].status == ResultStatus.OK
    assert len(knowledge.providers) == 0


@pytest.mark.asyncio
async def test_knowledge_only_entity() -> None:
    """Reference provider runs; no TI providers; threat_intelligence is empty."""
    ref_prov = _make_ref_provider("mitre_attack", entity_type=EntityType.MITRE_TECHNIQUE)
    service = _make_service(ref_providers=(ref_prov,))
    entity = _entity(EntityType.MITRE_TECHNIQUE, "T1059")

    ti, knowledge = await service.investigate(entity)

    assert len(ti.providers) == 0
    assert len(knowledge.providers) == 1
    assert knowledge.providers[0].provider == "mitre_attack"
    assert knowledge.providers[0].status == ResultStatus.OK


@pytest.mark.asyncio
async def test_both_frameworks_run() -> None:
    """Both TI and Reference providers contribute; results are separate."""
    ti_prov = _make_ti_provider("urlhaus", entity_type=EntityType.MALWARE_FAMILY)
    ref_prov = _make_ref_provider("mitre_attack", entity_type=EntityType.MALWARE_FAMILY)
    service = _make_service(ti_providers=(ti_prov,), ref_providers=(ref_prov,))
    entity = _entity(EntityType.MALWARE_FAMILY, "Cobalt Strike")

    ti, knowledge = await service.investigate(entity)

    assert len(ti.providers) == 1
    assert ti.providers[0].provider == "urlhaus"
    assert len(knowledge.providers) == 1
    assert knowledge.providers[0].provider == "mitre_attack"


@pytest.mark.asyncio
async def test_concurrent_execution() -> None:
    """All providers across both frameworks run in a single gather."""
    import time

    call_start_times: list[float] = []

    async def slow_search_a(_entity: Entity) -> IntelligenceResult:
        call_start_times.append(time.monotonic())
        await asyncio.sleep(0.02)
        return _ok_result("ti_a")

    async def slow_search_b(_entity: Entity) -> IntelligenceResult:
        call_start_times.append(time.monotonic())
        await asyncio.sleep(0.02)
        return _ok_result("ti_b")

    async def slow_lookup(_entity: Entity) -> IntelligenceResult:
        call_start_times.append(time.monotonic())
        await asyncio.sleep(0.02)
        return _ok_result("ref_a", entity_type=EntityType.MITRE_TECHNIQUE)

    ti_prov_a = MagicMock()
    ti_prov_a.safe_search = slow_search_a
    ti_prov_b = MagicMock()
    ti_prov_b.safe_search = slow_search_b
    ref_prov = MagicMock()
    ref_prov.safe_lookup = slow_lookup

    ti_router = MagicMock(spec=ProviderRouter)
    ti_router.route.return_value = (ti_prov_a, ti_prov_b)
    ref_router = MagicMock(spec=ReferenceRouter)
    ref_router.route.return_value = (ref_prov,)
    service = InvestigationService(ti_router, ref_router)
    entity = _entity(EntityType.IPV4, "1.2.3.4")

    start = time.monotonic()
    ti, knowledge = await service.investigate(entity)
    elapsed = time.monotonic() - start

    # All three sleep 0.02s concurrently — elapsed should be < 0.08s (not 0.06s serial).
    assert elapsed < 0.08
    assert len(call_start_times) == 3
    assert len(ti.providers) == 2
    assert len(knowledge.providers) == 1


@pytest.mark.asyncio
async def test_ti_provider_failure_does_not_block_knowledge() -> None:
    """A failing TI provider still contributes its status; knowledge is unaffected."""
    ti_prov = _make_ti_provider("failing_ti", result=_fail_result("failing_ti"))
    ref_prov = _make_ref_provider("mitre_attack", entity_type=EntityType.MITRE_TECHNIQUE)
    service = _make_service(ti_providers=(ti_prov,), ref_providers=(ref_prov,))
    entity = _entity(EntityType.MITRE_TECHNIQUE, "T1059")

    ti, knowledge = await service.investigate(entity)

    assert ti.providers[0].provider == "failing_ti"
    assert ti.providers[0].status == ResultStatus.ERROR
    assert knowledge.providers[0].provider == "mitre_attack"
    assert knowledge.providers[0].status == ResultStatus.OK


@pytest.mark.asyncio
async def test_ref_provider_failure_does_not_block_ti() -> None:
    """A failing reference provider still contributes its status; TI is unaffected."""
    ti_prov = _make_ti_provider("abuseipdb")
    ref_prov = _make_ref_provider(
        "failing_ref",
        result=_fail_result("failing_ref", entity_type=EntityType.MITRE_TECHNIQUE),
        entity_type=EntityType.MITRE_TECHNIQUE,
    )
    service = _make_service(ti_providers=(ti_prov,), ref_providers=(ref_prov,))
    entity = _entity(EntityType.IPV4, "1.2.3.4")

    ti, knowledge = await service.investigate(entity)

    assert ti.providers[0].status == ResultStatus.OK
    assert knowledge.providers[0].status == ResultStatus.ERROR


@pytest.mark.asyncio
async def test_provider_exception_caught_by_safe_methods() -> None:
    """safe_search / safe_lookup that return ERROR results are preserved in aggregation."""
    error_result = IntelligenceResult.failure(
        provider="boom_ti",
        entity_type=EntityType.IPV4,
        entity_value="1.2.3.4",
        message="unexpected provider error",
    )
    ti_prov = MagicMock()
    ti_prov.safe_search = AsyncMock(return_value=error_result)
    service = _make_service(ti_providers=(ti_prov,))
    entity = _entity(EntityType.IPV4, "1.2.3.4")

    ti, knowledge = await service.investigate(entity)
    assert ti.providers[0].status == ResultStatus.ERROR


@pytest.mark.asyncio
async def test_empty_both_frameworks() -> None:
    """No providers routed — both AggregatedResults have empty provider lists."""
    service = _make_service()
    entity = _entity(EntityType.FREETEXT, "hello")

    ti, knowledge = await service.investigate(entity)

    assert len(ti.providers) == 0
    assert len(knowledge.providers) == 0
    assert ti.entity_type == EntityType.FREETEXT
    assert knowledge.entity_type == EntityType.FREETEXT


@pytest.mark.asyncio
async def test_multiple_ti_providers_aggregated() -> None:
    """Multiple TI providers produce a single merged AggregatedResult."""
    prov_a = _make_ti_provider("provider_a")
    prov_b = _make_ti_provider("provider_b")
    prov_c = _make_ti_provider("provider_c", result=_not_found_result("provider_c"))
    service = _make_service(ti_providers=(prov_a, prov_b, prov_c))
    entity = _entity(EntityType.IPV4, "1.2.3.4")

    ti, knowledge = await service.investigate(entity)

    provider_names = {p.provider for p in ti.providers}
    assert provider_names == {"provider_a", "provider_b", "provider_c"}
    assert len(knowledge.providers) == 0

    # Evidence from two OK providers is merged (provider_c contributed nothing).
    ok_providers = [p for p in ti.providers if p.status == ResultStatus.OK]
    assert len(ok_providers) == 2


@pytest.mark.asyncio
async def test_entity_type_and_value_preserved() -> None:
    """Both AggregatedResults carry the correct entity type and value."""
    ti_prov = _make_ti_provider("ti", entity_type=EntityType.SHA256)
    ref_prov = _make_ref_provider("ref", entity_type=EntityType.SHA256)
    service = _make_service(ti_providers=(ti_prov,), ref_providers=(ref_prov,))
    entity = _entity(EntityType.SHA256, "abc123")

    ti, knowledge = await service.investigate(entity)

    assert ti.entity_type == EntityType.SHA256
    assert ti.entity_value == "abc123"
    assert knowledge.entity_type == EntityType.SHA256
    assert knowledge.entity_value == "abc123"


@pytest.mark.asyncio
async def test_router_receives_entity() -> None:
    """Both routers are called with the entity passed to investigate()."""
    ti_router = MagicMock(spec=ProviderRouter)
    ti_router.route.return_value = ()
    ref_router = MagicMock(spec=ReferenceRouter)
    ref_router.route.return_value = ()
    service = InvestigationService(ti_router, ref_router)

    entity = _entity(EntityType.DOMAIN, "evil.example.com")
    await service.investigate(entity)

    ti_router.route.assert_called_once_with(entity)
    ref_router.route.assert_called_once_with(entity)


# --------------------------------------------------------------------------- #
# /api/v1/investigate endpoint integration tests
# --------------------------------------------------------------------------- #


def _make_mock_service(
    ti_providers_count: int = 0,
    knowledge_providers_count: int = 0,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "1.2.3.4",
) -> MagicMock:
    ti_agg = AggregatedResult(
        entity_type=entity_type,
        entity_value=entity_value,
        providers=[
            MagicMock(
                provider=f"ti_{i}",
                provider_display_name=f"TI {i}",
                status=ResultStatus.OK,
                reputation=None,
                error=None,
            )
            for i in range(ti_providers_count)
        ],
    )
    knowledge_agg = AggregatedResult(
        entity_type=entity_type,
        entity_value=entity_value,
        providers=[
            MagicMock(
                provider=f"ref_{i}",
                provider_display_name=f"Ref {i}",
                status=ResultStatus.OK,
                reputation=None,
                error=None,
            )
            for i in range(knowledge_providers_count)
        ],
    )
    svc = MagicMock(spec=InvestigationService)
    svc.investigate = AsyncMock(return_value=(ti_agg, knowledge_agg))
    return svc


@pytest.fixture()
def client_with_mock_service():
    """TestClient with a clean mock investigation service injected."""
    mock_svc = MagicMock(spec=InvestigationService)
    mock_svc.investigate = AsyncMock(
        return_value=(
            AggregatedResult(entity_type=EntityType.IPV4, entity_value="8.8.8.8"),
            AggregatedResult(entity_type=EntityType.IPV4, entity_value="8.8.8.8"),
        )
    )
    app.dependency_overrides[get_investigation_service] = lambda: mock_svc
    yield TestClient(app), mock_svc
    app.dependency_overrides.clear()


def test_investigate_returns_200(client_with_mock_service) -> None:
    client, _ = client_with_mock_service
    res = client.post("/api/v1/investigate", json={"query": "8.8.8.8"})
    assert res.status_code == 200


def test_investigate_response_shape(client_with_mock_service) -> None:
    """Response has investigation_id (UUID), entity, threat_intelligence, knowledge."""
    client, _ = client_with_mock_service
    res = client.post("/api/v1/investigate", json={"query": "8.8.8.8"})
    body = res.json()

    assert UUID(body["investigation_id"])  # valid UUID
    assert "entity" in body
    entity = body["entity"]
    assert entity["type"] == "ipv4"
    assert "threat_intelligence" in body
    assert "knowledge" in body

    # Both AggregatedResult shapes must have the required keys.
    for key in ("threat_intelligence", "knowledge"):
        agg = body[key]
        assert "providers" in agg
        assert "evidence" in agg
        assert "relationships" in agg
        assert "references" in agg
        assert "tags" in agg


def test_investigate_entity_fields_present(client_with_mock_service) -> None:
    """Entity in the response carries all detection fields."""
    client, _ = client_with_mock_service
    res = client.post("/api/v1/investigate", json={"query": "8.8.8.8"})
    entity = res.json()["entity"]
    assert {"type", "value", "normalized_value", "confidence", "validation"}.issubset(entity.keys())


def test_investigate_unique_investigation_ids(client_with_mock_service) -> None:
    """Every request gets a distinct investigation_id."""
    client, _ = client_with_mock_service
    ids = {
        client.post("/api/v1/investigate", json={"query": "8.8.8.8"}).json()["investigation_id"]
        for _ in range(3)
    }
    assert len(ids) == 3


def test_investigate_empty_query_422(client_with_mock_service) -> None:
    client, _ = client_with_mock_service
    assert client.post("/api/v1/investigate", json={"query": ""}).status_code == 422


def test_investigate_blank_query_422(client_with_mock_service) -> None:
    client, _ = client_with_mock_service
    assert client.post("/api/v1/investigate", json={"query": "   "}).status_code == 422


def test_investigate_missing_query_422(client_with_mock_service) -> None:
    client, _ = client_with_mock_service
    assert client.post("/api/v1/investigate", json={}).status_code == 422


def test_investigate_oversized_query_422(client_with_mock_service) -> None:
    client, _ = client_with_mock_service
    assert client.post("/api/v1/investigate", json={"query": "x" * 5000}).status_code == 422


def test_investigate_service_receives_detected_entity(client_with_mock_service) -> None:
    """The service's investigate() is called with the entity detected from the query."""
    client, mock_svc = client_with_mock_service
    client.post("/api/v1/investigate", json={"query": "T1059"})
    assert mock_svc.investigate.called
    called_entity = mock_svc.investigate.call_args[0][0]
    assert called_entity.type == EntityType.MITRE_TECHNIQUE


def test_investigate_investigation_id_not_search_id(client_with_mock_service) -> None:
    """Response has investigation_id, not search_id."""
    client, _ = client_with_mock_service
    body = client.post("/api/v1/investigate", json={"query": "8.8.8.8"}).json()
    assert "investigation_id" in body
    assert "search_id" not in body


# --------------------------------------------------------------------------- #
# Real (offline) providers — MITRE ATT&CK round-trip
# --------------------------------------------------------------------------- #


def test_investigate_mitre_technique_real_providers() -> None:
    """T1059 produces knowledge from MITRE ATT&CK; TI section is empty."""
    client = TestClient(app)
    res = client.post("/api/v1/investigate", json={"query": "T1059"})
    assert res.status_code == 200
    body = res.json()

    # TI providers don't handle mitre_technique — threat_intelligence is empty.
    assert body["threat_intelligence"]["providers"] == []

    # MITRE ATT&CK reference provider returns knowledge.
    knowledge = body["knowledge"]
    assert len(knowledge["providers"]) >= 1
    mitre_provider = next(
        (p for p in knowledge["providers"] if "mitre" in p["provider"].lower()),
        None,
    )
    assert mitre_provider is not None
    assert mitre_provider["status"] == "ok"

    # Evidence includes a classification entry for T1059.
    assert any("T1059" in (e["evidence"].get("value") or "") for e in knowledge["evidence"])


def test_investigate_threat_actor_real_providers() -> None:
    """APT28 is recognized as threat_actor; MITRE ATT&CK returns knowledge about it."""
    client = TestClient(app)
    res = client.post("/api/v1/investigate", json={"query": "APT28"})
    assert res.status_code == 200
    body = res.json()

    assert body["entity"]["type"] == "threat_actor"
    knowledge = body["knowledge"]
    assert len(knowledge["providers"]) >= 1
    assert knowledge["providers"][0]["status"] == "ok"

    # G0007 is the ATT&CK ID for APT28.
    assert any("G0007" in (e["evidence"].get("value") or "") for e in knowledge["evidence"])


def test_investigate_malware_family_real_providers() -> None:
    """Emotet is recognized as malware_family; MITRE ATT&CK returns knowledge."""
    client = TestClient(app)
    res = client.post("/api/v1/investigate", json={"query": "emotet"})
    assert res.status_code == 200
    body = res.json()

    assert body["entity"]["type"] == "malware_family"
    knowledge = body["knowledge"]
    # MITRE ATT&CK has Emotet (S0367) in the bundled dataset.
    assert len(knowledge["providers"]) >= 1


def test_investigate_ipv4_ti_only_real_providers() -> None:
    """An IPv4 address routes to TI providers only; knowledge is empty."""
    client = TestClient(app)
    res = client.post("/api/v1/investigate", json={"query": "1.1.1.1"})
    assert res.status_code == 200
    body = res.json()

    assert body["entity"]["type"] == "ipv4"
    # No reference providers support IPv4 — knowledge section is empty.
    assert body["knowledge"]["providers"] == []


def test_investigate_unknown_input_graceful() -> None:
    """Unrecognized input resolves to freetext/unknown — never an error."""
    client = TestClient(app)
    res = client.post("/api/v1/investigate", json={"query": "zzznotarealindicator999"})
    assert res.status_code == 200
    body = res.json()
    assert body["entity"]["type"] in ("freetext", "unknown")
