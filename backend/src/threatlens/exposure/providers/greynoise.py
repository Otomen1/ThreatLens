"""GreyNoise Exposure Intelligence provider (Phase 5.3 — third provider).

Reports GreyNoise's own internet-noise/business-service classification for
IPv4 entities via its Context API (``/v2/noise/context/{ip}``) — a
fundamentally different kind of exposure fact than Shodan/Censys's scan
surface: not "what ports are open" but "does GreyNoise see this IP as known
internet-scanning background noise, or a recognized common business
service (RIOT)". Auth: a single API key from https://viz.greynoise.io,
sent as a ``key`` header (GreyNoise's own convention — not ``Authorization``).
Missing key yields a structured ``UNAUTHORIZED`` finding rather than an
exception; private/reserved/loopback IPs short-circuit to ``NOT_FOUND``
without a request — the same pattern every provider in this framework uses.

**Staying purely descriptive despite reputation-flavored data.** GreyNoise's
``classification`` field (benign/malicious/unknown) reads like a verdict, and
the framework's founding rule is "never judges maliciousness — that question
belongs to Threat Intelligence." This provider stays honest to that rule by
reporting GreyNoise's classification as a quoted, attributed third-party
statement ("GreyNoise classification: malicious") inside ``ExposureEvidence``
— the same pattern already used for Shodan's CVE flags and Censys's ASN
data — never computing, storing, or exposing a ThreatLens-owned score/band
from it. See ``docs/architecture/PHASE-5.3-GREYNOISE-PROVIDER.md``.

Only IPv4 is supported — GreyNoise's own scope, not a ThreatLens choice.
GreyNoise contributes no assets (no ports/certs/hostnames): every finding is
evidence-only, which is a legitimate, documented shape for a finding, not a
gap (``ExposureFinding.has_findings`` is true whenever evidence is
non-empty, no framework change needed).

Reuses ``providers/http.py``'s ``HttpClient`` — the same disclosed, narrow
exception to Phase 5.0's "``exposure/`` never imports from ``providers/``"
rule that ``ShodanProvider``/``CensysProvider`` already established.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ...entities.models import Entity
from ...entities.types import EntityType
from ...providers.http import HttpClient, ProviderNetworkError, ProviderTimeout
from ..cache import ExposureCache, InMemoryExposureCache
from ..models import (
    ExposureAuthType,
    ExposureCapability,
    ExposureEvidence,
    ExposureFinding,
    ExposureProviderHealth,
    ExposureProviderMetadata,
    ExposureProviderStatus,
    ExposureReference,
    ExposureStatus,
)
from ..normalize import opt_str, parse_iso_datetime, str_list
from ..provider import ExposureProvider

_NAME = "greynoise"
_DISPLAY = "GreyNoise"
_SUPPORTED = frozenset({EntityType.IPV4})
_HOST_REPORT_URL = "https://viz.greynoise.io/ip/{ip}"
_HOST_PATH = "/v2/noise/context/{ip}"
_HEALTH_PATH = "/ping"

_API_KEY_ENV = "GREYNOISE_API_KEY"
_BASE_URL_ENV = "GREYNOISE_BASE_URL"
_TIMEOUT_ENV = "GREYNOISE_TIMEOUT"
_ENABLED_ENV = "GREYNOISE_ENABLED"
_DEFAULT_BASE_URL = "https://api.greynoise.io"
_DEFAULT_TIMEOUT = 15.0

# Same rationale as every other provider in this framework: definitive
# answers are cached to respect rate limits; transient/auth failures are
# never cached so a fixed key or a recovered upstream is retried on the
# very next lookup.
_CACHE_TTL_SECONDS = 3600.0
_CACHEABLE_STATUSES = frozenset({ExposureStatus.OK, ExposureStatus.NOT_FOUND})

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


class GreyNoiseProvider(ExposureProvider):
    """Looks up GreyNoise's internet-noise/business-service classification for an IP."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        http_client: HttpClient | None = None,
        enabled: bool | None = None,
        cache: ExposureCache[ExposureFinding] | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.getenv(_API_KEY_ENV)
        resolved_base_url = base_url if base_url is not None else os.getenv(_BASE_URL_ENV)
        self._base_url = (resolved_base_url or _DEFAULT_BASE_URL).rstrip("/")
        resolved_timeout = (
            timeout if timeout is not None else _env_float(_TIMEOUT_ENV, _DEFAULT_TIMEOUT)
        )
        self._timeout = resolved_timeout
        self._http = http_client or HttpClient(timeout=resolved_timeout)
        self._enabled = enabled if enabled is not None else _env_truthy(_ENABLED_ENV, default=True)
        self._cache: ExposureCache[ExposureFinding] = (
            cache if cache is not None else InMemoryExposureCache()
        )

    @property
    def metadata(self) -> ExposureProviderMetadata:
        return ExposureProviderMetadata(
            name=_NAME,
            display_name=_DISPLAY,
            supported_entity_types=_SUPPORTED,
            capabilities=frozenset({ExposureCapability.INTERNET_NOISE}),
            priority=100,
            auth_type=ExposureAuthType.API_KEY,
            enabled=self._enabled,
        )

    async def lookup(self, entity: Entity) -> ExposureFinding:
        """Look up ``entity``'s GreyNoise classification (never raises).

        Definitive answers are cached in-memory on repeat lookups; transient
        failures and auth errors are never cached.
        """
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)

        cache_key = f"{entity.type.value}:{entity.value.strip().lower()}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        finding = await self._lookup_uncached(entity)
        if finding.status in _CACHEABLE_STATUSES:
            self._cache.set(cache_key, finding, ttl_seconds=_CACHE_TTL_SECONDS)
        return finding

    async def _lookup_uncached(self, entity: Entity) -> ExposureFinding:
        try:
            ip = ipaddress.ip_address(entity.value)
        except ValueError:
            return self._fail(
                entity, ExposureStatus.ERROR, "GreyNoise received an invalid IP address"
            )

        if not ip.is_global:
            # Private/reserved/loopback/link-local: no public GreyNoise data applies.
            return self._not_found(entity.type, entity.value)

        if not self._api_key:
            return self._fail(
                entity,
                ExposureStatus.UNAUTHORIZED,
                "GreyNoise API key not configured; set GREYNOISE_API_KEY "
                "(get one at https://viz.greynoise.io/)",
            )

        try:
            response = await self._http.get(
                f"{self._base_url}{_HOST_PATH.format(ip=entity.value)}",
                headers=self._auth_header(),
            )
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ExposureStatus.TIMEOUT,
                "GreyNoise request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity,
                ExposureStatus.ERROR,
                "Could not reach GreyNoise",
                retryable=True,
                detail=str(exc),
            )

        http_failure = self._map_http_status(entity, response.status_code)
        if http_failure is not None:
            return http_failure

        try:
            payload = response.json()
        except ValueError as exc:
            return self._fail(
                entity, ExposureStatus.ERROR, "GreyNoise returned malformed JSON", detail=str(exc)
            )

        if not isinstance(payload, Mapping):
            return self._fail(
                entity, ExposureStatus.ERROR, "GreyNoise returned an unexpected response"
            )

        return self._build(entity.type, entity.value, payload)

    async def normalize(self, raw: Any) -> ExposureFinding:
        """Map a raw GreyNoise context payload into a canonical finding.

        Entity identity is derived from the record's ``ip``.
        """
        data: Mapping[str, Any] = raw
        ip_str = opt_str(data, "ip") or "unknown"
        return self._build(EntityType.IPV4, ip_str, data)

    async def health(self) -> ExposureProviderHealth:
        """Verify configuration, reachability, and key validity against ``/ping``."""
        if not self.metadata.enabled:
            return ExposureProviderHealth(name=self.name, status=ExposureProviderStatus.DISABLED)
        if not self._api_key:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail="API key not configured",
            )
        try:
            response = await self._http.get(
                f"{self._base_url}{_HEALTH_PATH}", headers=self._auth_header()
            )
        except ProviderTimeout as exc:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.UNAVAILABLE,
                detail=f"GreyNoise request timed out: {exc}",
            )
        except ProviderNetworkError as exc:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.UNAVAILABLE,
                detail=f"Could not reach GreyNoise: {exc}",
            )
        if response.status_code in (401, 403):
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail="GreyNoise rejected the API key",
            )
        if response.status_code >= 400:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail=f"GreyNoise returned HTTP {response.status_code}",
            )
        return ExposureProviderHealth(name=self.name, status=ExposureProviderStatus.OPERATIONAL)

    async def configuration(self) -> dict[str, Any]:
        """Report configuration status — never the credential value itself."""
        return {
            "api_key_configured": bool(self._api_key),
            "base_url": self._base_url,
            "timeout": self._timeout,
            "enabled": self.metadata.enabled,
        }

    # --- internals -------------------------------------------------------- #

    def _auth_header(self) -> dict[str, str]:
        return {"key": self._api_key or ""}

    def _map_http_status(self, entity: Entity, code: int) -> ExposureFinding | None:
        if code == 404:
            return self._not_found(entity.type, entity.value)
        if code in (401, 403):
            return self._fail(
                entity,
                ExposureStatus.UNAUTHORIZED,
                "GreyNoise rejected the API key; check GREYNOISE_API_KEY",
            )
        if code == 429:
            return self._fail(
                entity, ExposureStatus.RATE_LIMITED, "GreyNoise rate limit reached", retryable=True
            )
        if code >= 400:
            return self._fail(entity, ExposureStatus.ERROR, f"GreyNoise returned HTTP {code}")
        return None

    def _build(
        self, entity_type: EntityType, entity_value: str, data: Mapping[str, Any]
    ) -> ExposureFinding:
        ip = opt_str(data, "ip") or entity_value
        evidence: list[ExposureEvidence] = []

        classification = opt_str(data, "classification")
        if classification:
            evidence.append(
                ExposureEvidence(
                    type="classification",
                    summary=f"GreyNoise classification: {classification}",
                    value=classification,
                )
            )

        is_noise = bool(data.get("noise"))
        if is_noise:
            evidence.append(
                ExposureEvidence(
                    type="internet_scanner",
                    summary="GreyNoise: observed scanning the internet (background noise)",
                    value="true",
                )
            )

        is_riot = bool(data.get("riot"))
        if is_riot:
            evidence.append(
                ExposureEvidence(
                    type="business_service",
                    summary="GreyNoise RIOT: recognized common business service",
                    value="true",
                )
            )

        name = opt_str(data, "name")
        if name and name.lower() != "unknown":
            evidence.append(
                ExposureEvidence(
                    type="name", summary=f"GreyNoise-identified name: {name}", value=name
                )
            )

        actor = opt_str(data, "actor")
        if actor and actor.lower() != "unknown":
            evidence.append(
                ExposureEvidence(
                    type="actor", summary=f"GreyNoise-identified actor: {actor}", value=actor
                )
            )

        if data.get("vpn"):
            vpn_service = opt_str(data, "vpn_service")
            summary = (
                f"GreyNoise: VPN service ({vpn_service})"
                if vpn_service
                else "GreyNoise: VPN service"
            )
            evidence.append(
                ExposureEvidence(type="vpn", summary=summary, value=vpn_service or "true")
            )

        metadata = data.get("metadata")
        if isinstance(metadata, Mapping):
            if metadata.get("tor"):
                evidence.append(
                    ExposureEvidence(type="tor", summary="GreyNoise: Tor exit node", value="true")
                )
            _add(evidence, "organization", "Organization", opt_str(metadata, "organization"))
            _add(evidence, "asn", "ASN", opt_str(metadata, "asn"))
            _add(evidence, "country", "Country", opt_str(metadata, "country"))
            _add(evidence, "city", "City", opt_str(metadata, "city"))

        last_seen = opt_str(data, "last_seen")
        if last_seen:
            evidence.append(
                ExposureEvidence(
                    type="last_seen",
                    summary=f"Last seen by GreyNoise: {last_seen}",
                    value=last_seen,
                    observed_at=parse_iso_datetime(last_seen),
                )
            )

        evidence.extend(
            ExposureEvidence(
                type="vulnerability",
                summary=f"GreyNoise associates this IP with: {cve}",
                value=cve,
            )
            for cve in str_list(data, "cve")
        )
        evidence.extend(
            ExposureEvidence(type="tag", summary=f"Tag: {tag}", value=tag)
            for tag in str_list(data, "tags")
        )

        category = (
            ExposureCapability.INTERNET_NOISE if (classification or is_noise or is_riot) else None
        )
        link = opt_str(data, "link") or _HOST_REPORT_URL.format(ip=ip)

        return ExposureFinding(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ExposureStatus.OK,
            category=category,
            summary=_summary(data),
            evidence=evidence,
            assets=[],
            references=[ExposureReference(title="GreyNoise IP report", url=link)],
            fetched_at=datetime.now(UTC),
        )


def _summary(data: Mapping[str, Any]) -> str:
    classification = opt_str(data, "classification") or "unknown"
    parts = [f"classification: {classification}"]
    if data.get("riot"):
        parts.append("RIOT (common business service)")
    if data.get("noise"):
        parts.append("internet scanner")
    return "GreyNoise: " + ", ".join(parts)


def _add(evidence: list[ExposureEvidence], etype: str, label: str, value: str | None) -> None:
    if value:
        evidence.append(ExposureEvidence(type=etype, summary=f"{label}: {value}", value=value))


def _env_truthy(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        return default
