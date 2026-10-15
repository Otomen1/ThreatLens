"""Signed-in-only metadata lookup, outside the public Threat Feed prefix."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ...poc.models import LookupRequest, Source, SourceResult
from ...poc.service import PocService
from ..auth import (
    owner_user_id,
    require_owner_identity,
    supabase_auth_config,
    verify_supabase_token,
)
from .threat_feed import get_threat_feed_service

router = APIRouter(prefix="/api/v1/poc", tags=["poc"])
_service: PocService | None = None


async def require_signed_in(request: Request) -> None:
    if getattr(request.state, "identity", None) is not None:
        require_owner_identity(request, signed_in=True)
        return
    config = supabase_auth_config()
    if config is None:
        raise HTTPException(status_code=503, detail="Sign-in service is unavailable")
    authorization = request.headers.get("authorization", "")
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    owner = owner_user_id()
    if not owner:
        raise HTTPException(status_code=503, detail="Owner access is not configured")
    identity = await verify_supabase_token(token, config)
    if identity is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    request.state.identity = identity
    require_owner_identity(request, signed_in=True)


def get_poc_service() -> PocService:
    global _service
    if _service is None:
        _service = PocService(get_threat_feed_service().storage)
    return _service


@router.post(
    "/lookup/{source}", response_model=SourceResult, dependencies=[Depends(require_signed_in)]
)
async def lookup(
    source: Source,
    body: LookupRequest,
    response: Response,
    service: Annotated[PocService, Depends(get_poc_service)],
) -> SourceResult:
    response.headers["Cache-Control"] = "private, no-store"
    return await service.lookup(source, body.cve, refresh=body.refresh)
