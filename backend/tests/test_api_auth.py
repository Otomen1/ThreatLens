import importlib

from fastapi.testclient import TestClient


def test_private_api_requires_supabase_session(monkeypatch) -> None:
    app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(app_module, "_API_KEY", "")
    monkeypatch.setattr(app_module, "supabase_auth_config", lambda: ("https://auth.test", "key"))

    async def reject(_token: str, _config: tuple[str, str]) -> bool:
        return False

    monkeypatch.setattr(app_module, "verify_supabase_token", reject)
    response = TestClient(app_module.app).get("/api/v1/system/config")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_private_api_accepts_verified_supabase_session(monkeypatch) -> None:
    app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(app_module, "_API_KEY", "")
    monkeypatch.setattr(app_module, "supabase_auth_config", lambda: ("https://auth.test", "key"))

    async def accept(token: str, config: tuple[str, str]) -> bool:
        return token == "valid" and config == ("https://auth.test", "key")

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

