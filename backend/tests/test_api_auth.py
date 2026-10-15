import importlib
import time

import pytest
from fastapi.testclient import TestClient

from threatlens.api.auth import VerifiedIdentity
from threatlens.api.rate_limit import LimitResult

OWNER = "00000000-0000-4000-8000-000000000001"


@pytest.fixture(autouse=True)
def isolated_limits(monkeypatch):
    module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(module, "consume_owner_request", lambda *args: LimitResult(True, 0))


def test_private_api_requires_supabase_session(monkeypatch) -> None:
    app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(app_module, "_API_KEY", "")
    monkeypatch.setattr(app_module, "supabase_auth_config", lambda: ("https://auth.test", "key"))

    async def reject(_token: str, _config: tuple[str, str]) -> VerifiedIdentity | None:
        return None

    monkeypatch.setattr(app_module, "verify_supabase_token", reject)
    response = TestClient(app_module.app).get("/api/v1/system/config")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_private_api_accepts_verified_supabase_session(monkeypatch) -> None:
    app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(app_module, "_API_KEY", "")
    monkeypatch.setattr(app_module, "supabase_auth_config", lambda: ("https://auth.test", "key"))

    async def accept(token: str, config: tuple[str, str]) -> VerifiedIdentity | None:
        return VerifiedIdentity(OWNER, time.time() + 60) if token == "valid" else None

    monkeypatch.setattr(app_module, "verify_supabase_token", accept)
    response = TestClient(app_module.app).get(
        "/api/v1/system/config", headers={"Authorization": "Bearer valid"}
    )
    assert response.status_code == 200


def test_public_feed_does_not_require_session(monkeypatch) -> None:
    app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(app_module, "_API_KEY", "")
    monkeypatch.setattr(app_module, "supabase_auth_config", lambda: ("https://auth.test", "key"))
    response = TestClient(app_module.app).get("/api/v1/threat-feed/summary")
    assert response.status_code == 200


def test_oversized_backup_is_rejected_before_parsing(monkeypatch) -> None:
    app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(app_module, "supabase_auth_config", lambda: None)
    response = TestClient(app_module.app).post(
        "/api/v1/backup/validate",
        content=b"{}",
        headers={"Content-Length": str(10_000_001)},
    )
    assert response.status_code == 413


def test_missing_production_authentication_fails_closed(monkeypatch):
    module = importlib.import_module("threatlens.api.app")
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setattr(module, "supabase_auth_config", lambda: None)
    monkeypatch.setattr(module, "_API_KEY", "")
    assert TestClient(module.app).get("/api/v1/workspace").status_code == 503
    assert TestClient(module.app).get("/api/v1/health").status_code == 200


def test_non_owner_cannot_access_private_endpoints(monkeypatch):
    module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(module, "supabase_auth_config", lambda: ("https://auth.test", "key"))

    async def other(*args):
        return VerifiedIdentity("00000000-0000-4000-8000-000000000002", time.time() + 60)

    monkeypatch.setattr(module, "verify_supabase_token", other)
    for path in ("/api/v1/workspace", "/api/v1/cases", "/api/v1/backup", "/api/v1/auth/me"):
        assert (
            TestClient(module.app).get(path, headers={"Authorization": "Bearer other"}).status_code
            == 403
        )


def test_verified_owner_me_and_api_key_limits(monkeypatch):
    module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(module, "supabase_auth_config", lambda: ("https://auth.test", "key"))

    async def owner(*args):
        return VerifiedIdentity(OWNER, time.time() + 60)

    monkeypatch.setattr(module, "verify_supabase_token", owner)
    response = TestClient(module.app).get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer owner"}
    )
    assert response.json() == {"user_id": OWNER, "owner": True}
    assert response.headers["cache-control"] == "private, no-store"
    monkeypatch.setattr(module, "consume_owner_request", lambda *args: LimitResult(False, 15))
    monkeypatch.setattr(module, "_API_KEY", "fixture-service-key")
    for headers in ({"Authorization": "Bearer owner"}, {"x-api-key": "fixture-service-key"}):
        response = TestClient(module.app).get("/api/v1/workspace", headers=headers)
        assert response.status_code == 429 and response.headers["retry-after"] == "15"
