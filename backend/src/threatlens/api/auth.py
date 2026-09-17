"""Authentication helpers for private API routes.

Supabase remains the identity provider.  The browser forwards its access
token and the API asks Supabase to validate it.  Successful validations are
cached briefly by token digest so a normal page does not perform one auth
request per API request.  Tokens and provider responses are never logged.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from threading import Lock

import httpx

_CACHE_TTL_SECONDS = 300.0
_CACHE_LIMIT = 256
_verified_tokens: OrderedDict[str, float] = OrderedDict()
_cache_lock = Lock()


def supabase_auth_config() -> tuple[str, str] | None:
    """Return the configured Supabase URL and publishable key, if available."""
    url = os.getenv("NEXT_PUBLIC_SUPABASE_URL", "").strip().rstrip("/")
    key = os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "").strip()
    if not url or not key:
        return None
    return url, key


def _cache_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _is_cached(token: str, now: float) -> bool:
    key = _cache_key(token)
    with _cache_lock:
        expires_at = _verified_tokens.get(key)
        if expires_at is None:
            return False
        if expires_at <= now:
            del _verified_tokens[key]
            return False
        _verified_tokens.move_to_end(key)
        return True


def _remember(token: str, now: float) -> None:
    key = _cache_key(token)
    with _cache_lock:
        _verified_tokens[key] = now + _CACHE_TTL_SECONDS
        _verified_tokens.move_to_end(key)
        while len(_verified_tokens) > _CACHE_LIMIT:
            _verified_tokens.popitem(last=False)


async def verify_supabase_token(token: str, config: tuple[str, str]) -> bool:
    """Validate one access token without exposing provider error details."""
    now = time.monotonic()
    if _is_cached(token, now):
        return True
    url, key = config
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.get(
                f"{url}/auth/v1/user",
                headers={"apikey": key, "Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError:
        return False
    if response.status_code != 200:
        return False
    try:
        user_id = response.json().get("id")
    except (ValueError, AttributeError):
        return False
    if not isinstance(user_id, str) or not user_id:
        return False
    _remember(token, now)
    return True

