"""Portable, versioned personal-data backup and safe merge restore."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from ...cases import Case, CaseService
from ...workspace import WorkspaceInvestigation, WorkspaceService
from .cases import get_case_service
from .workspace import get_workspace_service

router = APIRouter()
FORMAT = "threatlens-backup"
SCHEMA_VERSION = 1


class BackupBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: str = FORMAT
    schema_version: int = SCHEMA_VERSION
    exported_at: datetime
    application_version: str = "1.2.0"
    investigations: list[WorkspaceInvestigation] = Field(default_factory=list)
    cases: list[Case] = Field(default_factory=list)
    digest: str = ""


class RestorePreview(BaseModel):
    valid: bool
    investigations: int
    cases: int
    conflicts: int
    errors: list[str] = Field(default_factory=list)


class RestoreResult(BaseModel):
    investigations_added: int
    investigations_updated: int
    investigations_skipped: int
    cases_added: int
    cases_updated: int
    cases_skipped: int


def _digest(bundle: BackupBundle) -> str:
    payload = bundle.model_dump(mode="json", exclude={"digest"})
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _errors(bundle: BackupBundle) -> list[str]:
    errors: list[str] = []
    if bundle.format != FORMAT:
        errors.append("Unsupported backup format.")
    if bundle.schema_version != SCHEMA_VERSION:
        errors.append("Unsupported backup schema version.")
    if not bundle.digest or bundle.digest != _digest(bundle):
        errors.append("Backup integrity check failed.")
    return errors


@router.get("/api/v1/backup")
def export_backup(
    workspace: Annotated[WorkspaceService, Depends(get_workspace_service)],
    cases: Annotated[CaseService, Depends(get_case_service)],
) -> Response:
    bundle = BackupBundle(
        exported_at=datetime.now(UTC),
        investigations=workspace.snapshot(),
        cases=cases.snapshot(),
    )
    bundle = bundle.model_copy(update={"digest": _digest(bundle)})
    return Response(
        content=bundle.model_dump_json(indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="threatlens-backup.json"'},
    )


@router.post("/api/v1/backup/validate", response_model=RestorePreview)
def validate_backup(
    bundle: BackupBundle,
    workspace: Annotated[WorkspaceService, Depends(get_workspace_service)],
    cases: Annotated[CaseService, Depends(get_case_service)],
) -> RestorePreview:
    errors = _errors(bundle)
    workspace_ids = {record.id for record in workspace.snapshot()}
    case_ids = {record.id for record in cases.snapshot()}
    conflicts = sum(record.id in workspace_ids for record in bundle.investigations)
    conflicts += sum(record.id in case_ids for record in bundle.cases)
    return RestorePreview(
        valid=not errors,
        investigations=len(bundle.investigations),
        cases=len(bundle.cases),
        conflicts=conflicts,
        errors=errors,
    )


@router.post("/api/v1/backup/restore", response_model=RestoreResult)
def restore_backup(
    bundle: BackupBundle,
    workspace: Annotated[WorkspaceService, Depends(get_workspace_service)],
    cases: Annotated[CaseService, Depends(get_case_service)],
) -> RestoreResult:
    errors = _errors(bundle)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    workspace_result = workspace.merge_snapshot(bundle.investigations)
    case_result = cases.merge_snapshot(bundle.cases)
    return RestoreResult(
        investigations_added=workspace_result[0],
        investigations_updated=workspace_result[1],
        investigations_skipped=workspace_result[2],
        cases_added=case_result[0],
        cases_updated=case_result[1],
        cases_skipped=case_result[2],
    )
