"""Private Identity Intelligence status and lookup routes."""

from __future__ import annotations

import os
import re
import time
from collections import deque
from datetime import UTC, datetime
from threading import Lock
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query

from ...entities.types import EntityType
from ...identity import IDENTITY_FRAMEWORK_VERSION
from ...identity.runtime import config as identity_config
from ...identity.runtime import registry as identity_registry
from ...identity.runtime import service as identity_service
from ...providers.http import HttpClient, ProviderHttpError, ProviderTimeout
from ...search import detect
from ..schemas import (
    MAX_QUERY_LENGTH,
    IdentityEmailCheckRequest,
    IdentityEmailCheckResponse,
    IdentityFrameworkStatus,
    IdentityProviderStatusInfo,
    PasswordHashSuffix,
    PasswordRangeResponse,
)

router = APIRouter()

# Identity Intelligence reports source-attributed exposure facts and never
# computes a compromised/safe verdict.
_PASSWORD_PREFIX = re.compile(r"^[A-Fa-f0-9]{5}$")
_password_client = HttpClient(timeout=10, max_retries=1)
_password_requests: deque[float] = deque()
_password_lock = Lock()


def _password_request_allowed() -> bool:
    raw_limit = os.getenv("IDENTITY_PASSWORD_RATE_LIMIT_PER_MINUTE", "30")
    limit = int(raw_limit) if raw_limit.isdigit() else 30
    now = time.monotonic()
    with _password_lock:
        while _password_requests and now - _password_requests[0] >= 60:
            _password_requests.popleft()
        if len(_password_requests) >= limit:
            return False
        _password_requests.append(now)
        return True


@router.get("/api/v1/identity", response_model=IdentityFrameworkStatus)
async def identity_framework_status(
    value: Annotated[str | None, Query(max_length=MAX_QUERY_LENGTH)] = None,
) -> IdentityFrameworkStatus:
    """Report framework and provider status; optionally preserve legacy lookup."""
    summary = None
    if value is not None and value.strip():
        summary = await identity_service.investigate(detect(value))
    provider_states = []
    for provider in identity_registry.providers:
        health = await provider.health()
        configuration = await provider.configuration()
        provider_states.append(
            IdentityProviderStatusInfo(
                name=provider.name,
                display_name=provider.metadata.display_name,
                enabled=provider.enabled,
                configured=bool(configuration.get("configured")),
                status=health.status.value,
                detail=health.detail,
            )
        )
    count = len(identity_registry)
    return IdentityFrameworkStatus(
        status="ready",
        message=f"{count} provider(s) registered",
        framework_version=IDENTITY_FRAMEWORK_VERSION,
        providers_registered=count,
        enabled=identity_config.enabled,
        providers=provider_states,
        summary=summary,
    )


@router.post("/api/v1/identity/email/check", response_model=IdentityEmailCheckResponse)
async def check_email(request: IdentityEmailCheckRequest) -> IdentityEmailCheckResponse:
    entity = detect(request.email.strip())
    if entity.type is not EntityType.EMAIL:
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    summary, cache_hit = await identity_service.investigate_with_cache_state(
        entity, refresh=request.refresh
    )
    cache_status: Literal["hit", "miss", "refreshed", "disabled"]
    if not identity_config.enabled:
        cache_status = "disabled"
    elif cache_hit:
        cache_status = "hit"
    elif request.refresh:
        cache_status = "refreshed"
    else:
        cache_status = "miss"
    return IdentityEmailCheckResponse(
        summary=summary, cache_status=cache_status, checked_at=datetime.now(UTC)
    )


@router.get(
    "/api/v1/identity/password-range/{prefix}", response_model=PasswordRangeResponse
)
async def password_range(prefix: str) -> PasswordRangeResponse:
    normalized = prefix.upper()
    if not _PASSWORD_PREFIX.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="Invalid hash prefix")
    if not _password_request_allowed():
        raise HTTPException(status_code=429, detail="Password check rate limit reached")
    try:
        response = await _password_client.get(
            f"https://api.pwnedpasswords.com/range/{normalized}",
            headers={"Add-Padding": "true"},
        )
    except ProviderTimeout as exc:
        raise HTTPException(status_code=504, detail="Password dataset timed out") from exc
    except ProviderHttpError as exc:
        raise HTTPException(status_code=502, detail="Password dataset unavailable") from exc
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="Password dataset rate limited")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Password dataset unavailable")
    suffixes: list[PasswordHashSuffix] = []
    for line in response.text.splitlines():
        suffix, separator, raw_count = line.partition(":")
        if not separator or not re.fullmatch(r"[A-Fa-f0-9]{35}", suffix):
            continue
        try:
            count = int(raw_count.strip())
        except ValueError:
            continue
        suffixes.append(PasswordHashSuffix(suffix=suffix.upper(), count=max(0, count)))
    return PasswordRangeResponse(
        prefix=normalized, suffixes=suffixes, checked_at=datetime.now(UTC)
    )
