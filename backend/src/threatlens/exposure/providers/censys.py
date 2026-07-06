"""Censys Exposure Intelligence provider (Phase 5.2, PAT migration 5.2.1).

Reports open ports, running services, TLS certificates, reverse-DNS
hostnames, and hosting/ASN facts for IPv4/IPv6 entities — purely
descriptive, never a reputation score or malicious/benign verdict.

Two auth modes, resolved once at construction, PAT preferred:

1. ``CENSYS_PERSONAL_ACCESS_TOKEN`` set → ``Authorization: Bearer <token>``
   against the current Censys Platform API (``api.platform.censys.io``).
2. Else ``CENSYS_API_ID`` + ``CENSYS_API_SECRET`` both set → HTTP Basic auth
   against the legacy Search API v2 (``search.censys.io/api``) — kept for
   backward compatibility, unchanged from Phase 5.2.
3. Else → every lookup returns a structured ``UNAUTHORIZED`` finding, never
   an exception; ``health()`` reports ``DISABLED`` (not ``DEGRADED`` — no
   credentials configured at all is treated as "not set up", distinct from
   "configured but rejected").

**Honesty note on the Platform API path:** the PAT-authenticated endpoint
(``/v3/global/asset/host/{ip}``) and health probe (``/v3/organizations``) are
a best-effort mapping from Censys's documented Platform API conventions, not
verified against a live account — this sandbox's egress policy blocks
arbitrary third-party API hosts the same way it already blocked a live
Shodan check, so no endpoint in this whole framework has been exercised
against a real upstream. The normalization path defensively unwraps either a
flat ``result`` (legacy shape) or ``result.host`` (a plausible Platform
asset-envelope shape) and tolerates missing fields throughout (same as
``ShodanProvider``), so an imperfect endpoint guess degrades to a sparse
"ok" finding rather than a crash — but real-world verification against a
live Platform account is recommended before relying on this in production.

Only IPv4/IPv6 are supported, mirroring ``ShodanProvider``'s scope decision
for the same reason: Censys's host view is IP-keyed, and domain/hostname
exposure would need an extra resolution step the API doesn't offer as a
single, unambiguous call — deferred rather than guessed at.

Reuses ``providers/http.py``'s ``HttpClient`` — the same disclosed, narrow
exception to Phase 5.0's "``exposure/`` never imports from ``providers/``"
rule that ``ShodanProvider`` already established (see
``docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md``). No file under
``providers/`` is modified here either.
"""

from __future__ import annotations

import base64
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
    ExposureAsset,
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

_NAME = "censys"
_DISPLAY = "Censys"
_SUPPORTED = frozenset({EntityType.IPV4, EntityType.IPV6})
_HOST_REPORT_URL = "https://search.censys.io/hosts/{ip}"

_PAT_ENV = "CENSYS_PERSONAL_ACCESS_TOKEN"
_API_ID_ENV = "CENSYS_API_ID"
_API_SECRET_ENV = "CENSYS_API_SECRET"
_BASE_URL_ENV = "CENSYS_BASE_URL"
_TIMEOUT_ENV = "CENSYS_TIMEOUT"
_ENABLED_ENV = "CENSYS_ENABLED"

# Legacy Search API v2 (Basic auth) vs. current Platform API (Bearer PAT) —
# different hosts, different endpoint shapes. See the module docstring's
# "Honesty note" for how much of the Platform side is verified vs. best-effort.
_DEFAULT_LEGACY_BASE_URL = "https://search.censys.io/api"
_DEFAULT_PLATFORM_BASE_URL = "https://api.platform.censys.io"
_LEGACY_HOST_PATH = "/v2/hosts/{ip}"
_PLATFORM_HOST_PATH = "/v3/global/asset/host/{ip}"
_LEGACY_HEALTH_PATH = "/v2/account"
_PLATFORM_HEALTH_PATH = "/v3/organizations"
_DEFAULT_TIMEOUT = 15.0

# Same rationale as ShodanProvider: definitive answers are cached to respect
# rate limits; transient/auth failures are never cached so a fixed
# credential or a recovered upstream is retried on the very next lookup.
_CACHE_TTL_SECONDS = 3600.0
_CACHEABLE_STATUSES = frozenset({ExposureStatus.OK, ExposureStatus.NOT_FOUND})

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


class CensysProvider(ExposureProvider):
    """Looks up open-port and hosting exposure for an IP against Censys."""

    def __init__(
        self,
        *,
        personal_access_token: str | None = None,
        api_id: str | None = None,
        api_secret: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        http_client: HttpClient | None = None,
        enabled: bool | None = None,
        cache: ExposureCache[ExposureFinding] | None = None,
    ) -> None:
        self._pat = (
            personal_access_token if personal_access_token is not None else os.getenv(_PAT_ENV)
        )
        self._api_id = api_id if api_id is not None else os.getenv(_API_ID_ENV)
        self._api_secret = api_secret if api_secret is not None else os.getenv(_API_SECRET_ENV)

        # PAT takes precedence; legacy ID+Secret is the backward-compatible
        # fallback; "none" means every lookup/health check short-circuits
        # without a request.
        if self._pat:
            self._auth_mode = "pat"
        elif self._api_id and self._api_secret:
            self._auth_mode = "basic"
        else:
            self._auth_mode = "none"

        resolved_base_url = base_url if base_url is not None else os.getenv(_BASE_URL_ENV)
        if resolved_base_url:
            self._base_url = resolved_base_url.rstrip("/")
        else:
            default = (
                _DEFAULT_PLATFORM_BASE_URL if self._auth_mode == "pat" else _DEFAULT_LEGACY_BASE_URL
            )
            self._base_url = default.rstrip("/")

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
            capabilities=frozenset(
                {
                    ExposureCapability.OPEN_PORTS,
                    ExposureCapability.SERVICES,
                    ExposureCapability.CERTIFICATES,
                    ExposureCapability.HOSTING,
                    ExposureCapability.ASN,
                }
            ),
            priority=100,
            auth_type=ExposureAuthType.API_KEY,
            enabled=self._enabled,
        )

    async def lookup(self, entity: Entity) -> ExposureFinding:
        """Look up ``entity``'s exposure and return a canonical finding (never raises).

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
            return self._fail(entity, ExposureStatus.ERROR, "Censys received an invalid IP address")

        if not ip.is_global:
            # Private/reserved/loopback/link-local: no public Censys exposure applies.
            return self._not_found(entity.type, entity.value)

        if self._auth_mode == "none":
            return self._fail(
                entity,
                ExposureStatus.UNAUTHORIZED,
                "Censys credentials not configured; set CENSYS_PERSONAL_ACCESS_TOKEN "
                "(preferred; https://search.censys.io/account/api) or the legacy "
                "CENSYS_API_ID + CENSYS_API_SECRET pair",
            )

        host_path = _PLATFORM_HOST_PATH if self._auth_mode == "pat" else _LEGACY_HOST_PATH
        try:
            response = await self._http.get(
                f"{self._base_url}{host_path.format(ip=entity.value)}",
                headers=self._auth_header(),
            )
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ExposureStatus.TIMEOUT,
                "Censys request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity,
                ExposureStatus.ERROR,
                "Could not reach Censys",
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
                entity, ExposureStatus.ERROR, "Censys returned malformed JSON", detail=str(exc)
            )

        if not isinstance(payload, Mapping):
            return self._fail(
                entity, ExposureStatus.ERROR, "Censys returned an unexpected response"
            )

        result = _extract_host_result(payload)
        if result is None:
            return self._fail(
                entity, ExposureStatus.ERROR, "Censys returned an unexpected response"
            )

        return self._build(entity.type, entity.value, result)

    async def normalize(self, raw: Any) -> ExposureFinding:
        """Map a raw Censys host-lookup payload into a canonical finding.

        Accepts the full API envelope (``{"result": {...}}``, either the
        legacy flat shape or a Platform-style ``result.host`` nesting) or a
        bare host object; entity identity is derived from ``ip``.
        """
        envelope: Any = raw
        extracted = _extract_host_result(envelope) if isinstance(envelope, Mapping) else None
        data: Mapping[str, Any] = extracted if extracted is not None else envelope
        ip_str = opt_str(data, "ip") or "unknown"
        try:
            entity_type = (
                EntityType.IPV6
                if isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv6Address)
                else EntityType.IPV4
            )
        except ValueError:
            entity_type = EntityType.IPV4
        return self._build(entity_type, ip_str, data)

    async def health(self) -> ExposureProviderHealth:
        """Verify configuration, reachability, and credential validity.

        No credentials configured at all → ``DISABLED`` (distinct from
        "configured but rejected", which is ``DEGRADED``).
        """
        if not self.metadata.enabled:
            return ExposureProviderHealth(name=self.name, status=ExposureProviderStatus.DISABLED)
        if self._auth_mode == "none":
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DISABLED,
                detail="No credentials configured (CENSYS_PERSONAL_ACCESS_TOKEN or "
                "CENSYS_API_ID/CENSYS_API_SECRET)",
            )
        health_path = _PLATFORM_HEALTH_PATH if self._auth_mode == "pat" else _LEGACY_HEALTH_PATH
        try:
            response = await self._http.get(
                f"{self._base_url}{health_path}", headers=self._auth_header()
            )
        except ProviderTimeout as exc:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.UNAVAILABLE,
                detail=f"Censys request timed out: {exc}",
            )
        except ProviderNetworkError as exc:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.UNAVAILABLE,
                detail=f"Could not reach Censys: {exc}",
            )
        if response.status_code in (401, 403):
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail="Censys rejected the API credentials",
            )
        if response.status_code >= 400:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail=f"Censys returned HTTP {response.status_code}",
            )
        return ExposureProviderHealth(name=self.name, status=ExposureProviderStatus.OPERATIONAL)

    async def configuration(self) -> dict[str, Any]:
        """Report configuration status — never the credential values themselves."""
        return {
            "auth_mode": self._auth_mode,
            "api_credentials_configured": self._auth_mode != "none",
            "base_url": self._base_url,
            "timeout": self._timeout,
            "enabled": self.metadata.enabled,
        }

    # --- internals -------------------------------------------------------- #

    def _auth_header(self) -> dict[str, str]:
        if self._auth_mode == "pat":
            return {"Authorization": f"Bearer {self._pat}"}
        token = base64.b64encode(f"{self._api_id}:{self._api_secret}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _map_http_status(self, entity: Entity, code: int) -> ExposureFinding | None:
        if code == 404:
            return self._not_found(entity.type, entity.value)
        if code in (401, 403):
            return self._fail(
                entity,
                ExposureStatus.UNAUTHORIZED,
                "Censys rejected the credentials; check CENSYS_PERSONAL_ACCESS_TOKEN or "
                "CENSYS_API_ID/CENSYS_API_SECRET",
            )
        if code == 429:
            return self._fail(
                entity, ExposureStatus.RATE_LIMITED, "Censys rate limit reached", retryable=True
            )
        if code >= 400:
            return self._fail(entity, ExposureStatus.ERROR, f"Censys returned HTTP {code}")
        return None

    def _build(
        self, entity_type: EntityType, entity_value: str, result: Mapping[str, Any]
    ) -> ExposureFinding:
        ip = opt_str(result, "ip") or entity_value
        raw_services = result.get("services")
        services: list[Mapping[str, Any]] = [
            service
            for service in (raw_services if isinstance(raw_services, list) else [])
            if isinstance(service, Mapping)
        ]

        assets: list[ExposureAsset] = []
        evidence: list[ExposureEvidence] = []

        for service in services:
            assets.append(_service_asset(service))
            certificate = _certificate_asset(service)
            if certificate is not None:
                assets.append(certificate)

        dns = result.get("dns")
        reverse_dns = dns.get("reverse_dns") if isinstance(dns, Mapping) else None
        if isinstance(reverse_dns, Mapping):
            assets.extend(
                ExposureAsset(asset_type="hostname", value=name)
                for name in str_list(reverse_dns, "names")
            )

        autonomous_system = result.get("autonomous_system")
        has_hosting_data = isinstance(autonomous_system, Mapping)
        if isinstance(autonomous_system, Mapping):
            asn = autonomous_system.get("asn")
            _add(evidence, "asn", "ASN", f"AS{asn}" if isinstance(asn, int) else None)
            _add(evidence, "organization", "Organization", opt_str(autonomous_system, "name"))

        location = result.get("location")
        if isinstance(location, Mapping):
            has_hosting_data = True
            _add(evidence, "country", "Country", opt_str(location, "country"))
            _add(evidence, "city", "City", opt_str(location, "city"))

        last_updated = opt_str(result, "last_updated_at")
        if last_updated:
            evidence.append(
                ExposureEvidence(
                    type="last_seen",
                    summary=f"Last seen by Censys: {last_updated}",
                    value=last_updated,
                    observed_at=parse_iso_datetime(last_updated),
                )
            )

        category = (
            ExposureCapability.OPEN_PORTS
            if services
            else ExposureCapability.HOSTING
            if has_hosting_data
            else None
        )

        return ExposureFinding(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ExposureStatus.OK,
            category=category,
            summary=_summary(result, len(services)),
            evidence=evidence,
            assets=assets,
            references=[
                ExposureReference(title="Censys host report", url=_HOST_REPORT_URL.format(ip=ip))
            ],
            fetched_at=datetime.now(UTC),
        )


def _extract_host_result(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Unwrap a host record from either API envelope shape.

    Legacy Search API v2 puts host fields directly on ``result``. The
    Platform API's asset envelopes are, per Censys's general REST
    conventions, plausibly nested one level deeper (``result.host``) — this
    is the one part of this provider not verified against a live account
    (see the module docstring). Falling back to ``result`` itself if there
    is no nested ``host`` (or if ``result`` already looks like a host record)
    keeps the legacy path exactly as before.
    """
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    nested = result.get("host")
    if "ip" not in result and isinstance(nested, Mapping):
        return nested
    return result


def _summary(result: Mapping[str, Any], service_count: int) -> str:
    parts = [f"{service_count} open port(s)" if service_count else "no open ports on record"]
    autonomous_system = result.get("autonomous_system")
    org = opt_str(autonomous_system, "name") if isinstance(autonomous_system, Mapping) else None
    if org:
        parts.append(f"hosted by {org}")
    return "Censys: " + ", ".join(parts)


def _service_asset(service: Mapping[str, Any]) -> ExposureAsset:
    port = service.get("port")
    attributes: dict[str, Any] = {
        "transport": (opt_str(service, "transport_protocol") or "tcp").lower()
    }
    service_name = opt_str(service, "service_name")
    if service_name:
        attributes["service"] = service_name
    software = service.get("software")
    first_software = software[0] if isinstance(software, list) and software else None
    if isinstance(first_software, Mapping):
        product = opt_str(first_software, "product")
        if product:
            attributes["product"] = product
        version = opt_str(first_software, "version")
        if version:
            attributes["version"] = version
    return ExposureAsset(
        asset_type="open_port",
        value=str(port) if isinstance(port, int) else "unknown",
        last_seen=parse_iso_datetime(opt_str(service, "observed_at")),
        attributes=attributes,
    )


def _certificate_asset(service: Mapping[str, Any]) -> ExposureAsset | None:
    tls = service.get("tls")
    certificates = tls.get("certificates") if isinstance(tls, Mapping) else None
    leaf = certificates.get("leaf_data") if isinstance(certificates, Mapping) else None
    if not isinstance(leaf, Mapping):
        return None

    subject = opt_str(leaf, "subject_dn")
    issuer = opt_str(leaf, "issuer_dn")
    fingerprint = opt_str(leaf, "fingerprint") or opt_str(service, "certificate")

    attributes: dict[str, Any] = {}
    if issuer:
        attributes["issuer"] = issuer
    if fingerprint:
        attributes["fingerprint"] = fingerprint

    return ExposureAsset(
        asset_type="certificate",
        value=subject or fingerprint or "certificate",
        attributes=attributes,
    )


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
