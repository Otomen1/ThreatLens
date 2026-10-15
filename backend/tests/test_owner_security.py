"""Offline regressions for identity caches and durable owner request protection."""

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from threatlens.api import auth
from threatlens.api.rate_limit import RequestLimiter

OWNER = "00000000-0000-4000-8000-000000000001"


def jwt(expiry):
    encoded = base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


@pytest.mark.asyncio
async def test_cache_identity_expiry_and_project_separation(monkeypatch):
    original = httpx.AsyncClient
    calls = []

    def respond(request):
        calls.append(request.url.host)
        return httpx.Response(200, json={"id": OWNER})

    monkeypatch.setattr(
        auth.httpx,
        "AsyncClient",
        lambda **kw: original(transport=httpx.MockTransport(respond), **kw),
    )
    auth._verified_tokens.clear()
    now = time.time()
    token = jwt(now + 30)
    first = await auth.verify_supabase_token(token, ("https://first.test", "key"))
    assert first is not None and first.user_id == OWNER and first.expires_at <= now + 30
    assert await auth.verify_supabase_token(token, ("https://first.test", "key")) == first
    assert len(calls) == 1
    await auth.verify_supabase_token(token, ("https://second.test", "key"))
    assert len(calls) == 2
    assert await auth.verify_supabase_token(jwt(now - 1), ("https://first.test", "key")) is None


@pytest.mark.asyncio
async def test_malformed_and_rejected_upstream_are_not_authenticated(monkeypatch):
    original = httpx.AsyncClient
    for status, payload in [(401, {}), (200, {"id": "not-a-user-id"}), (200, [])]:
        transport = httpx.MockTransport(
            lambda request, status=status, payload=payload: httpx.Response(status, json=payload)
        )
        monkeypatch.setattr(
            auth.httpx,
            "AsyncClient",
            lambda transport=transport, **kw: original(transport=transport, **kw),
        )
        assert await auth.verify_supabase_token("opaque", ("https://auth.test", "key")) is None


def test_production_ignores_local_bypass(monkeypatch):
    monkeypatch.setenv("THREATLENS_ENV", "development")
    monkeypatch.setenv("THREATLENS_ALLOW_UNAUTHENTICATED_LOCAL", "true")
    monkeypatch.delenv("VERCEL", raising=False)
    assert auth.local_auth_bypass()
    monkeypatch.setenv("VERCEL", "1")
    assert not auth.local_auth_bypass()


@pytest.mark.parametrize("backend", ["file", "sqlite", "memory"])
def test_rate_limit_atomicity_expiry_and_scope(tmp_path, backend):
    args = (backend, "", str(tmp_path / "limits.db"), str(tmp_path / "limits.json"))
    one, two = RequestLimiter(*args), RequestLimiter(*args)
    if backend == "memory":
        two = one
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(
            workers.map(
                lambda i: (one if i % 2 else two).consume("owner:private", 3, now=120), range(12)
            )
        )
    assert sum(result.allowed for result in results) == 3
    assert not two.consume("owner:private", 3, now=150).allowed
    assert two.consume("owner:private", 3, now=180).allowed
    assert two.consume("owner:password", 1, now=150).allowed
    assert two.consume("different:private", 1, now=150).allowed
    assert two.consume("owner:password", 1, now=151).retry_after == 29
