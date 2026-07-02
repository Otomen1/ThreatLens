"""Operational-readiness & health endpoint tests (Phase 3.17).

Every check is read-only and offline: no intelligence provider is ever invoked
and no third-party API quota is consumed. The single network path
(``/health/ai`` when AI is enabled) is exercised against an
``httpx.MockTransport``, never a live Ollama server.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from threatlens.ai.config import AISettings
from threatlens.api import health as health_mod
from threatlens.api.app import app
from threatlens.providers.base import IntelligenceProvider
from threatlens.providers.http import HttpClient
from threatlens.reasoning import ENGINE_VERSION
from threatlens.reference.base import ReferenceProvider

client = TestClient(app)

# The router is mounted at the root (infra probes) and under /api/v1 (frontend).
_MOUNTS = ("", "/api/v1")


# --------------------------------------------------------------------------- #
# Liveness & version
# --------------------------------------------------------------------------- #


class TestLiveness:
    @pytest.mark.parametrize("prefix", _MOUNTS)
    def test_health_is_ok(self, prefix: str) -> None:
        res = client.get(f"{prefix}/health")
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "ok"
        assert body["service"] == "threatlens"
        assert body["version"]
        assert body["uptime_seconds"] >= 0
        assert body["started_at"] and body["timestamp"]

    @pytest.mark.parametrize("prefix", _MOUNTS)
    def test_version_reports_components(self, prefix: str) -> None:
        body = client.get(f"{prefix}/version").json()
        assert body["reasoning_engine"] == ENGINE_VERSION  # frozen engine version
        assert body["api"] == "v1"
        assert body["platform"]
        assert set(body["build"]) == {"commit", "timestamp"}


# --------------------------------------------------------------------------- #
# Readiness
# --------------------------------------------------------------------------- #


class TestReadiness:
    def test_ready_when_core_is_up(self) -> None:
        res = client.get("/ready")
        assert res.status_code == 200
        body = res.json()
        assert body["ready"] is True
        names = {check["name"] for check in body["checks"]}
        assert names == {"detection_engine", "reasoning_engine", "knowledge_base"}
        assert all(check["ready"] for check in body["checks"])

    def test_not_ready_returns_503(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # No knowledge datasets loaded → the core cannot fully serve → 503.
        monkeypatch.setattr(health_mod, "_loaded_dataset_count", lambda: 0)
        res = client.get("/ready")
        assert res.status_code == 503
        body = res.json()
        assert body["ready"] is False
        kb = next(c for c in body["checks"] if c["name"] == "knowledge_base")
        assert kb["ready"] is False


# --------------------------------------------------------------------------- #
# Provider configuration (never calls a provider / consumes quota)
# --------------------------------------------------------------------------- #


class TestProviders:
    def test_lists_all_ti_providers(self) -> None:
        body = client.get("/health/providers").json()
        names = {p["name"] for p in body["providers"]}
        assert names == {"malwarebazaar", "urlhaus", "abuseipdb", "otx"}
        assert body["total"] == 4
        for provider in body["providers"]:
            assert provider["entity_types"]  # each declares supported types
            assert isinstance(provider["requires_auth"], bool)
            assert isinstance(provider["configured"], bool)

    def test_configured_when_keys_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "k")  # covers malwarebazaar + urlhaus
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
        monkeypatch.setenv("OTX_API_KEY", "k")
        body = client.get("/health/providers").json()
        assert body["status"] == "ok"
        assert body["configured"] == 4
        assert all(p["configured"] for p in body["providers"])

    def test_degraded_when_keys_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "ABUSE_CH_AUTH_KEY",
            "MALWAREBAZAAR_AUTH_KEY",
            "URLHAUS_AUTH_KEY",
            "ABUSEIPDB_API_KEY",
            "OTX_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        body = client.get("/health/providers").json()
        assert body["status"] == "degraded"  # honest: no keys → nothing configured
        assert body["configured"] == 0
        assert not any(p["configured"] for p in body["providers"])


# --------------------------------------------------------------------------- #
# Knowledge datasets (offline; never touches the network)
# --------------------------------------------------------------------------- #


class TestKnowledge:
    def test_all_bundled_datasets_are_healthy(self) -> None:
        body = client.get("/health/knowledge").json()
        names = {d["name"] for d in body["datasets"]}
        assert {"mitre_attack", "nvd", "cwe", "capec"} <= names
        assert body["status"] == "ok"  # bundled offline datasets are healthy
        assert all(d["healthy"] for d in body["datasets"])
        assert all(d["offline"] for d in body["datasets"])

    def test_eager_dataset_reports_version(self) -> None:
        body = client.get("/health/knowledge").json()
        mitre = next(d for d in body["datasets"] if d["name"] == "mitre_attack")
        assert mitre["loaded"] is True
        assert mitre["dataset_version"]


# --------------------------------------------------------------------------- #
# AI subsystem (the only endpoint that may touch the network)
# --------------------------------------------------------------------------- #


def _mock_client(handler: object) -> HttpClient:
    return HttpClient(max_retries=0, transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


class TestAIHealthRoute:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AI_ENABLED", raising=False)
        body = client.get("/health/ai").json()
        assert body["status"] == "disabled"
        assert body["enabled"] is False
        assert body["reachable"] is False
        assert body["detail"]  # a friendly note, never a stack trace


class TestAIProbe:
    async def test_disabled_makes_no_network_call(self) -> None:
        called = False

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return httpx.Response(200, json={})

        out = await health_mod._probe_ai(AISettings(enabled=False), http=_mock_client(handler))
        assert out.status == "disabled"
        assert called is False  # a disabled provider is never probed

    async def test_reachable_with_model_available(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/tags"  # reachability, not generation
            return httpx.Response(
                200, json={"models": [{"name": "qwen3:4b"}, {"name": "llama3:8b"}]}
            )

        settings = AISettings(enabled=True, provider="ollama", ollama_model="qwen3:4b")
        out = await health_mod._probe_ai(settings, http=_mock_client(handler))
        assert out.status == "ok"
        assert out.reachable is True
        assert out.model_available is True

    async def test_reachable_but_model_missing(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"models": [{"name": "llama3:8b"}]})

        settings = AISettings(enabled=True, provider="ollama", ollama_model="qwen3:4b")
        out = await health_mod._probe_ai(settings, http=_mock_client(handler))
        assert out.status == "ok"
        assert out.reachable is True
        assert out.model_available is False

    async def test_connection_refused_is_unavailable(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        out = await health_mod._probe_ai(AISettings(enabled=True), http=_mock_client(handler))
        assert out.status == "unavailable"
        assert out.reachable is False
        assert "Traceback" not in (out.detail or "")  # never leak internals

    async def test_http_500_is_unavailable(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        out = await health_mod._probe_ai(AISettings(enabled=True), http=_mock_client(handler))
        assert out.status == "unavailable"
        assert out.reachable is False

    async def test_unsupported_provider_is_unavailable(self) -> None:
        out = await health_mod._probe_ai(
            AISettings(enabled=True, provider="openai"),
            http=_mock_client(lambda _r: httpx.Response(200)),
        )
        assert out.status == "unavailable"
        assert out.reachable is False


# --------------------------------------------------------------------------- #
# Read-only guarantee: health never runs an investigation
# --------------------------------------------------------------------------- #


def test_health_never_invokes_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every read-only endpoint must work even if provider lookups would fail."""

    async def boom(self: object, entity: object) -> object:
        raise AssertionError("health endpoints must never invoke a provider lookup")

    monkeypatch.setattr(IntelligenceProvider, "safe_search", boom)
    monkeypatch.setattr(IntelligenceProvider, "search", boom)
    monkeypatch.setattr(ReferenceProvider, "safe_lookup", boom)
    monkeypatch.setattr(ReferenceProvider, "lookup", boom)

    for path in ("/health", "/ready", "/health/providers", "/health/knowledge", "/version"):
        assert client.get(path).status_code in (200, 503)
