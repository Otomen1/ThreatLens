"""Tests for WorkspaceSettings (Phase 8.0 config).

No prior test covered this module directly; added alongside the Vercel
read-only-filesystem fix, which depends on ``THREATLENS_WORKSPACE_DIR``
being the one, already-existing way to override the storage path.
"""

from __future__ import annotations

from pathlib import Path

from threatlens.workspace import WorkspaceSettings


class TestWorkspaceSettingsFromEnv:
    def test_defaults_to_data_workspace_when_unset(self) -> None:
        assert WorkspaceSettings.from_env({}).storage_dir == Path("data/workspace")

    def test_reads_threatlens_workspace_dir_override(self) -> None:
        settings = WorkspaceSettings.from_env(
            {"THREATLENS_WORKSPACE_DIR": "/tmp/threatlens/workspace"}
        )
        assert settings.storage_dir == Path("/tmp/threatlens/workspace")

    def test_blank_value_falls_back_to_default(self) -> None:
        settings = WorkspaceSettings.from_env({"THREATLENS_WORKSPACE_DIR": "   "})
        assert settings.storage_dir == Path("data/workspace")

    def test_unrelated_environment_variables_are_ignored(self) -> None:
        settings = WorkspaceSettings.from_env({"SOME_OTHER_VAR": "/should/not/matter"})
        assert settings.storage_dir == Path("data/workspace")
