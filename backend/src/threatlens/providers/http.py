"""Minimal async HTTP client for intelligence providers.

Wraps :mod:`httpx` with a request timeout and bounded retry-with-backoff for
transient failures (timeouts, transport errors, 5xx), surfacing typed errors
that providers map onto :class:`~threatlens.providers.results.IntelligenceResult`
statuses. Deliberately small: no caching and no circuit breaker (later phases).

A custom ``transport`` can be injected so tests exercise the retry/error logic
against ``httpx.MockTransport`` without touching the network.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_RETRIES = 2
_DEFAULT_BACKOFF = 0.5
_USER_AGENT = "ThreatLens/0.1 (+https://github.com/Otomen1/ThreatLens)"


class ProviderHttpError(Exception):
    """Base class for HTTP failures surfaced to a provider."""


class ProviderTimeout(ProviderHttpError):
    """The request timed out after exhausting retries."""


class ProviderNetworkError(ProviderHttpError):
    """A transport/connection error (or 5xx) persisted after retries."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A minimal, decoded view of an HTTP response."""

    status_code: int
    text: str

    def json(self) -> Any:
        """Parse the body as JSON (raises ``ValueError`` on malformed input)."""
        return json.loads(self.text)


class HttpClient:
    """Async HTTP client with timeout and transient-failure retries."""

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = _DEFAULT_RETRIES,
        backoff: float = _DEFAULT_BACKOFF,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff = backoff
        self._transport = transport

    async def post_form(
        self,
        url: str,
        *,
        data: dict[str, str],
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """POST form-encoded ``data``; retry transient failures, then raise."""
        merged_headers = {"User-Agent": _USER_AGENT, **(headers or {})}
        return await self._send(lambda client: client.post(url, data=data, headers=merged_headers))

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """GET ``url`` with query ``params``; retry transient failures, then raise."""
        merged_headers = {"User-Agent": _USER_AGENT, **(headers or {})}
        return await self._send(
            lambda client: client.get(url, params=params, headers=merged_headers)
        )

    async def _send(
        self,
        request: Callable[[httpx.AsyncClient], Awaitable[httpx.Response]],
    ) -> HttpResponse:
        """Run ``request`` with timeout + bounded retry-with-backoff.

        Returns the response for any non-5xx status (4xx included — those are
        definitive answers the provider maps). Raises :class:`ProviderTimeout`
        or :class:`ProviderNetworkError` if a transient failure persists.
        """
        last_error: ProviderHttpError | None = None

        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            for attempt in range(self._max_retries + 1):
                try:
                    response = await request(client)
                except httpx.TimeoutException as exc:
                    last_error = ProviderTimeout(str(exc) or "request timed out")
                except httpx.TransportError as exc:
                    last_error = ProviderNetworkError(str(exc) or "transport error")
                else:
                    if response.status_code < 500:
                        return HttpResponse(status_code=response.status_code, text=response.text)
                    last_error = ProviderNetworkError(f"server error {response.status_code}")

                if attempt < self._max_retries:
                    await asyncio.sleep(self._backoff * (2**attempt))

        assert last_error is not None  # loop always sets it before exhausting
        raise last_error
