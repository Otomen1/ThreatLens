"""Verified Supabase identities and an explicit single-owner authorization policy."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
from uuid import UUID

import httpx
from fastapi import HTTPException, Request

_CACHE_TTL_SECONDS = 300.0
_CACHE_LIMIT = 256


@dataclass(frozen=True)
class VerifiedIdentity:
    user_id: str
    expires_at: float
    credential: str = "supabase"


_verified_tokens: OrderedDict[str, VerifiedIdentity] = OrderedDict()
_cache_lock = Lock()


def owner_user_id() -> str | None:
    try:
        return str(UUID(os.getenv("THREATLENS_OWNER_USER_ID", "")))
    except ValueError:
        return None


def local_auth_bypass() -> bool:
    return (
        not os.getenv("VERCEL")
        and os.getenv("THREATLENS_ENV", "").lower() in {"development", "test"}
        and os.getenv("THREATLENS_ALLOW_UNAUTHENTICATED_LOCAL", "").lower() == "true"
    )


def supabase_auth_config() -> tuple[str, str] | None:
    url = os.getenv("NEXT_PUBLIC_SUPABASE_URL", "").strip().rstrip("/")
    key = os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "").strip()
    if not url or not key:
        return None
    return url, key


def _cache_key(token: str, config: tuple[str, str]) -> str:
    return hashlib.sha256(("|".join(config) + "|" + token).encode()).hexdigest()


def _token_expiry(token: str, now: float) -> float:
    # Only read AFTER Supabase verifies this exact token; this never authenticates it.
    try:
        segment = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        expiry = claims.get("exp")
        if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
            return min(now + _CACHE_TTL_SECONDS, float(expiry))
    except (ValueError, IndexError, TypeError, AttributeError):
        pass
    # Missing expiry prevents cache reuse, not upstream verification.
    return now


async def verify_supabase_token(token: str, config: tuple[str, str]) -> VerifiedIdentity | None:
    now = time.time()
    digest = _cache_key(token, config)
    with _cache_lock:
        cached = _verified_tokens.get(digest)
        if cached and cached.expires_at > now:
            _verified_tokens.move_to_end(digest)
            return cached
        _verified_tokens.pop(digest, None)
    url, key = config
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.get(
                f"{url}/auth/v1/user",
                headers={"apikey": key, "Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            return None
        user_id = str(UUID(response.json()["id"]))
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        return None
    now = time.time()
    identity = VerifiedIdentity(user_id, _token_expiry(token, now))
    if identity.expires_at < now:
        return None
    if identity.expires_at > now:
        with _cache_lock:
            _verified_tokens[digest] = identity
            _verified_tokens.move_to_end(digest)
            while len(_verified_tokens) > _CACHE_LIMIT:
                _verified_tokens.popitem(last=False)
    return identity


def require_owner_identity(request: Request, *, signed_in: bool = False) -> VerifiedIdentity:
    identity = getattr(request.state, "identity", None)
    if not isinstance(identity, VerifiedIdentity):
        raise HTTPException(status_code=401, detail="Authentication required")
    if signed_in and identity.credential != "supabase":
        raise HTTPException(status_code=401, detail="Sign in to use this feature")
    owner = owner_user_id()
    if not owner:
        raise HTTPException(status_code=503, detail="Owner access is not configured")
    if identity.user_id != owner:
        raise HTTPException(status_code=403, detail="This personal workspace is owner-only")
    return identity
