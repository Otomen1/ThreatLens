"""Integration tests for GET /api/v1/system/config (Section 3)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app

client = TestClient(app)

_ALLOWED_KEYS = {"name", "display_name", "configured", "enabled"}


def test_provider_items_expose_only_operational_metadata() -> None:
    body = client.get("/api/v1/system/config").json()
    for provider in body["threat_intelligence"] + body["knowledge"]:
        assert set(provider) == _ALLOWED_KEYS
        assert isinstance(provider["configured"], bool)
        assert isinstance(provider["enabled"], bool)


def test_configured_true_when_keys_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "k")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setenv("OTX_API_KEY", "k")
    body = client.get("/api/v1/system/config").json()
    assert all(p["configured"] for p in body["threat_intelligence"])


def test_configured_false_when_keys_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "ABUSE_CH_AUTH_KEY",
        "MALWAREBAZAAR_AUTH_KEY",
        "URLHAUS_AUTH_KEY",
        "ABUSEIPDB_API_KEY",
        "OTX_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    body = client.get("/api/v1/system/config").json()
    assert not any(p["configured"] for p in body["threat_intelligence"])


def test_ai_disabled_by_default() -> None:
    body = client.get("/api/v1/system/config").json()
    assert body["ai"] == {"provider": "ollama", "enabled": False, "model": None}


def test_ai_enabled_reports_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3:4b")
    body = client.get("/api/v1/system/config").json()
    assert body["ai"] == {"provider": "ollama", "enabled": True, "model": "qwen3:4b"}


def test_no_secret_values_ever_appear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "shh-do-not-leak-this")
    monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "another-shh-value")
    res = client.get("/api/v1/system/config")
    assert "shh-do-not-leak-this" not in res.text
    assert "another-shh-value" not in res.text
    # And no field name that would suggest a raw credential is being carried.
    for banned in ("key", "token", "secret", "password", "bearer"):
        assert banned not in res.text.lower()
