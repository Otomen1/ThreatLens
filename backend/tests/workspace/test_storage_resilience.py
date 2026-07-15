"""Regression tests for the Vercel read-only-filesystem production fix.

Before this fix, ``api/routes/workspace.py`` built its ``WorkspaceService``
(and thus called ``LocalFileStorage.__init__``'s ``mkdir``) at module import
time. On a deployment whose only writable path is ``/tmp`` (e.g. Vercel),
that ``mkdir`` raised ``OSError``, which failed the import of
``threatlens.api.app`` itself — taking every route down, not just the
workspace ones. The fix makes workspace-storage construction lazy (first
request, not import) and makes ``THREATLENS_WORKSPACE_DIR`` (already the
existing override mechanism, see test_config.py) the supported way to point
at a writable directory in such environments.

All offline; no real filesystem read-only mount is needed — a path whose
parent component is a plain file can never be `mkdir`'d, which is a
portable, unmocked stand-in for "the filesystem said no."
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import threatlens.api.routes.workspace as workspace_routes
from threatlens.api.app import app
from threatlens.workspace import WorkspaceStorageError


@pytest.fixture()
def broken_storage_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point THREATLENS_WORKSPACE_DIR at a path that can never be created,
    and reset the process-wide lazy singleton so the next call re-attempts
    construction under this environment."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    bad_root = blocker / "workspace"
    monkeypatch.setenv("THREATLENS_WORKSPACE_DIR", str(bad_root))
    monkeypatch.setattr(workspace_routes, "_workspace_service", None)
    return bad_root


class TestAppImportSurvivesBrokenStorage:
    def test_reimporting_the_app_module_succeeds_under_a_broken_storage_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The exact production failure mode: importing threatlens.api.app
        must never fail merely because the configured workspace storage path
        can't be created. Forces a genuinely fresh import with the broken
        path already set, rather than reusing this process's already-
        (successfully-)imported app."""
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        monkeypatch.setenv("THREATLENS_WORKSPACE_DIR", str(blocker / "workspace"))

        affected = [
            name
            for name in sys.modules
            if name == "threatlens.api.app" or name.startswith("threatlens.api.routes")
        ]
        saved = {name: sys.modules[name] for name in affected}
        for name in affected:
            del sys.modules[name]
        try:
            module = importlib.import_module("threatlens.api.app")
            assert module.app is not None
        finally:
            for name in affected:
                del sys.modules[name]
            sys.modules.update(saved)


class TestUnrelatedRoutesSurviveBrokenWorkspaceStorage:
    def test_health_route_unaffected(self, broken_storage_env: Path) -> None:
        client = TestClient(app)
        assert client.get("/health").status_code == 200

    def test_investigate_route_unaffected(self, broken_storage_env: Path) -> None:
        client = TestClient(app)
        res = client.post("/api/v1/investigate", json={"query": "8.8.8.8"})
        assert res.status_code == 200

    def test_workspace_route_fails_cleanly_without_crashing_the_app(
        self, broken_storage_env: Path
    ) -> None:
        # raise_server_exceptions=False mirrors real ASGI serving (uvicorn,
        # Vercel): an unhandled exception in one route becomes a 500
        # response, not a crashed process. TestClient's default of
        # re-raising for debugging is deliberately opted out of here.
        client = TestClient(app, raise_server_exceptions=False)
        res = client.post(
            "/api/v1/workspace", json={"title": "Case", "investigation_type": "ipv4"}
        )
        assert res.status_code == 500
        # the app itself is still alive and serving unrelated routes:
        assert client.get("/health").status_code == 200

    def test_get_workspace_service_raises_storage_error_directly(
        self, broken_storage_env: Path
    ) -> None:
        with pytest.raises(WorkspaceStorageError):
            workspace_routes.get_workspace_service()


class TestLazySingletonRecoversAfterAFailedAttempt:
    def test_a_failed_attempt_does_not_permanently_poison_later_calls(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Only success is memoized (see the module-level comment in
        api/routes/workspace.py) — a prior failure under a bad path must not
        prevent a later call, under a corrected path, from succeeding.
        Mirrors redeploying with the env var fixed."""
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        monkeypatch.setenv("THREATLENS_WORKSPACE_DIR", str(blocker / "workspace"))
        monkeypatch.setattr(workspace_routes, "_workspace_service", None)
        with pytest.raises(WorkspaceStorageError):
            workspace_routes.get_workspace_service()

        monkeypatch.setenv("THREATLENS_WORKSPACE_DIR", str(tmp_path / "workspace"))
        service = workspace_routes.get_workspace_service()
        assert service is not None
