from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.api.experience import start_summary
from threatlens.api.routes import cases, workspace
from threatlens.api.routes.poc import require_signed_in
from threatlens.system.metrics import registry


def test_start_summary_is_bounded_passive_and_safe(monkeypatch):
    now = datetime.now(UTC)
    records = [
        SimpleNamespace(
            id=str(i),
            title=f"Record {i}",
            updated_at=now + timedelta(seconds=i),
            status=SimpleNamespace(value="open"),
            detection_package=None,
        )
        for i in range(8)
    ]
    monkeypatch.setattr(
        workspace, "get_workspace_service", lambda: SimpleNamespace(snapshot=lambda: records)
    )
    monkeypatch.setattr(
        cases,
        "get_case_service",
        lambda: SimpleNamespace(
            snapshot=lambda: [SimpleNamespace(status=SimpleNamespace(value="open"))]
        ),
    )
    monkeypatch.setattr(
        registry,
        "provider_events",
        [
            {"provider": "virustotal", "status_code": 401, "payload": "secret"},
            {"provider": "otx", "status_code": 429},
            {"provider": "virustotal", "status_code": 200},
            {"provider": "https://user:secret@bad", "status_code": 500},
        ],
    )
    result = start_summary()
    assert len(result.recent) == 5
    assert result.recent[0].id == "7"
    assert result.investigations == 8
    assert result.open_cases == 1
    assert [issue.provider for issue in result.provider_issues] == ["otx"]
    assert "secret" not in result.model_dump_json()


def test_start_summary_preserves_other_sections_on_failure(monkeypatch):
    def broken():
        raise RuntimeError("private failure")

    monkeypatch.setattr(workspace, "get_workspace_service", broken)
    monkeypatch.setattr(cases, "get_case_service", lambda: SimpleNamespace(snapshot=lambda: []))
    result = start_summary()
    assert result.availability["workspace"] is False
    assert result.availability["cases"] is True
    assert result.investigations is None
    assert "private failure" not in result.model_dump_json()


def test_start_route_precedes_dynamic_record_and_is_private(monkeypatch):
    monkeypatch.setattr(
        workspace, "get_workspace_service", lambda: SimpleNamespace(snapshot=lambda: [])
    )
    monkeypatch.setattr(cases, "get_case_service", lambda: SimpleNamespace(snapshot=lambda: []))
    app.dependency_overrides[require_signed_in] = lambda: None
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/workspace/start-summary")
    finally:
        app.dependency_overrides.pop(require_signed_in, None)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json()["recent"] == []


def test_start_summary_fails_closed_without_sign_in_configuration(monkeypatch):
    from threatlens.api.routes import poc

    monkeypatch.setattr(poc, "supabase_auth_config", lambda: None)
    response = TestClient(app).get("/api/v1/workspace/start-summary")
    assert response.status_code == 503


def test_start_summary_requires_sign_in_before_reading_storage(monkeypatch):
    from threatlens.api.routes import poc

    monkeypatch.setattr(poc, "supabase_auth_config", lambda: ("https://auth.test", "key"))
    monkeypatch.setattr(
        workspace,
        "get_workspace_service",
        lambda: (_ for _ in ()).throw(AssertionError("Storage must not be read")),
    )
    response = TestClient(app).get("/api/v1/workspace/start-summary")
    assert response.status_code == 401
