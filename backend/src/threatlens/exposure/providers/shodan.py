"""Shodan Exposure Intelligence provider (Phase 5.1 — first concrete provider).

Reports open ports, running services, TLS certificates, and hosting/ASN facts
for IPv4/IPv6 entities via Shodan's Host API (``/shodan/host/{ip}``) —
purely descriptive, never a reputation score or malicious/benign verdict.
Auth: a Shodan API key from https://account.shodan.io, read from
``SHODAN_API_KEY``. A missing key yields a structured ``UNAUTHORIZED``
finding rather than an exception; private/reserved/loopback IPs short-circuit
to ``NOT_FOUND`` without a request — both mirror ``providers/abuseipdb.py``'s
established pattern for a single-IP-lookup provider.

Only IPv4/IPv6 are supported. Shodan's host lookup is IP-keyed; reporting
exposure for a domain would require an extra DNS-resolution hop the API
doesn't provide as a single, clearly-supported call — deferred rather than
guessed at (see ``docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md``).

Deliberate, narrow exception to Phase 5.0's "``exposure/`` never imports from
``providers/``" rule: this module reuses ``providers/http.py``'s
``HttpClient`` — a generic, dependency-free async transport wrapper with no
Threat Intelligence types, models, or business logic — instead of
duplicating an HTTP layer. Exposure Intelligence still shares zero models,
zero registry, and zero provider logic with Threat Intelligence; only this
content-free transport utility is shared, the same way both already depend
on ``httpx``.
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

_NAME = "shodan"
_DISPLAY = "Shodan"
_SUPPORTED = frozenset({EntityType.IPV4, EntityType.IPV6})
_HOST_REPORT_URL = "https://www.shodan.io/host/{ip}"

_API_KEY_ENV = "SHODAN_API_KEY"
_BASE_URL_ENV = "SHODAN_BASE_URL"
_TIMEOUT_ENV = "SHODAN_TIMEOUT"
_ENABLED_ENV = "SHODAN_ENABLED"
_DEFAULT_BASE_URL = "https://api.shodan.io"
_DEFAULT_TIMEOUT = 15.0

# Definitive answers are cached to respect Shodan's rate limits; transient
# failures (timeout/rate-limited/error) and auth failures are never cached so
# a fixed key or a recovered upstream is retried on the very next lookup.
_CACHE_TTL_SECONDS = 3600.0
_CACHEABLE_STATUSES = frozenset({ExposureStatus.OK, ExposureStatus.NOT_FOUND})

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


class ShodanProvider(ExposureProvider):
    """Looks up open-port and hosting exposure for an IP against Shodan."""

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

        Definitive answers (found / confirmed not found) are served from an
        in-memory cache on repeat lookups; transient failures and auth errors
        are never cached, so a fixed key or a recovered upstream is retried
        on the very next call.
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
            return self._fail(entity, ExposureStatus.ERROR, "Shodan received an invalid IP address")

        if not ip.is_global:
            # Private/reserved/loopback/link-local: no public Shodan exposure applies.
            return self._not_found(entity.type, entity.value)

        if not self._api_key:
            return self._fail(
                entity,
                ExposureStatus.UNAUTHORIZED,
                "Shodan API key not configured; set SHODAN_API_KEY "
                "(get one at https://account.shodan.io/)",
            )

        try:
            response = await self._http.get(
                f"{self._base_url}/shodan/host/{entity.value}",
                params={"key": self._api_key},
            )
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ExposureStatus.TIMEOUT,
                "Shodan request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity,
                ExposureStatus.ERROR,
                "Could not reach Shodan",
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
                entity, ExposureStatus.ERROR, "Shodan returned malformed JSON", detail=str(exc)
            )

        if not isinstance(payload, Mapping):
            return self._fail(
                entity, ExposureStatus.ERROR, "Shodan returned an unexpected response"
            )

        return self._build(entity.type, entity.value, payload)

    async def normalize(self, raw: Any) -> ExposureFinding:
        """Map a raw Shodan host-lookup payload into a canonical finding.

        Entity identity is derived from the record's ``ip_str``.
        """
        data: Mapping[str, Any] = raw
        ip_str = opt_str(data, "ip_str") or "unknown"
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
        """Verify configuration, reachability, and API-key validity against ``/api-info``."""
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
                f"{self._base_url}/api-info", params={"key": self._api_key}
            )
        except ProviderTimeout as exc:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.UNAVAILABLE,
                detail=f"Shodan request timed out: {exc}",
            )
        except ProviderNetworkError as exc:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.UNAVAILABLE,
                detail=f"Could not reach Shodan: {exc}",
            )
        if response.status_code in (401, 403):
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail="Shodan rejected the API key",
            )
        if response.status_code >= 400:
            return ExposureProviderHealth(
                name=self.name,
                status=ExposureProviderStatus.DEGRADED,
                detail=f"Shodan returned HTTP {response.status_code}",
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

    def _map_http_status(self, entity: Entity, code: int) -> ExposureFinding | None:
        if code == 404:
            return self._not_found(entity.type, entity.value)
        if code in (401, 403):
            return self._fail(
                entity,
                ExposureStatus.UNAUTHORIZED,
                "Shodan rejected the API key; check SHODAN_API_KEY",
            )
        if code == 429:
            return self._fail(
                entity, ExposureStatus.RATE_LIMITED, "Shodan rate limit reached", retryable=True
            )
        if code >= 400:
            return self._fail(entity, ExposureStatus.ERROR, f"Shodan returned HTTP {code}")
        return None

    def _build(
        self, entity_type: EntityType, entity_value: str, data: Mapping[str, Any]
    ) -> ExposureFinding:
        ip = opt_str(data, "ip_str") or entity_value
        raw_banners = data.get("data")
        banners: list[Mapping[str, Any]] = [
            banner
            for banner in (raw_banners if isinstance(raw_banners, list) else [])
            if isinstance(banner, Mapping)
        ]

        assets: list[ExposureAsset] = []
        evidence: list[ExposureEvidence] = []

        for banner in banners:
            assets.append(_port_asset(banner))
            certificate = _certificate_asset(banner)
            if certificate is not None:
                assets.append(certificate)
            evidence.extend(_banner_evidence(banner))

        assets.extend(
            ExposureAsset(asset_type="hostname", value=host) for host in str_list(data, "hostnames")
        )
        assets.extend(
            ExposureAsset(asset_type="domain", value=domain) for domain in str_list(data, "domains")
        )

        _add(evidence, "operating_system", "Operating system", opt_str(data, "os"))
        _add(evidence, "organization", "Organization", opt_str(data, "org"))
        _add(evidence, "isp", "ISP", opt_str(data, "isp"))
        _add(evidence, "asn", "ASN", opt_str(data, "asn"))
        _add(evidence, "country", "Country", opt_str(data, "country_name"))
        _add(evidence, "city", "City", opt_str(data, "city"))

        last_update = opt_str(data, "last_update")
        if last_update:
            evidence.append(
                ExposureEvidence(
                    type="last_seen",
                    summary=f"Last seen by Shodan: {last_update}",
                    value=last_update,
                    observed_at=parse_iso_datetime(last_update),
                )
            )

        evidence.extend(
            ExposureEvidence(
                type="vulnerability",
                summary=f"Shodan flagged a possible vulnerability: {cve}",
                value=cve,
            )
            for cve in _vuln_ids(data.get("vulns"))
        )
        evidence.extend(
            ExposureEvidence(type="tag", summary=f"Tag: {tag}", value=tag)
            for tag in str_list(data, "tags")
        )

        ports = data.get("ports")
        port_count = len(ports) if isinstance(ports, list) else len(banners)
        category = (
            ExposureCapability.OPEN_PORTS
            if port_count
            else ExposureCapability.HOSTING
            if (opt_str(data, "org") or opt_str(data, "isp") or opt_str(data, "asn"))
            else None
        )

        return ExposureFinding(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ExposureStatus.OK,
            category=category,
            summary=_summary(data, port_count),
            evidence=evidence,
            assets=assets,
            references=[
                ExposureReference(title="Shodan host report", url=_HOST_REPORT_URL.format(ip=ip))
            ],
            fetched_at=datetime.now(UTC),
        )


def _summary(data: Mapping[str, Any], port_count: int) -> str:
    parts = [f"{port_count} open port(s)" if port_count else "no open ports on record"]
    org = opt_str(data, "org")
    if org:
        parts.append(f"hosted by {org}")
    return "Shodan: " + ", ".join(parts)


def _port_asset(banner: Mapping[str, Any]) -> ExposureAsset:
    port = banner.get("port")
    attributes: dict[str, Any] = {"transport": opt_str(banner, "transport") or "tcp"}
    product = opt_str(banner, "product")
    if product:
        attributes["product"] = product
    version = opt_str(banner, "version")
    if version:
        attributes["version"] = version
    shodan_meta = banner.get("_shodan")
    if isinstance(shodan_meta, Mapping):
        module = opt_str(shodan_meta, "module")
        if module:
            attributes["service"] = module
    return ExposureAsset(
        asset_type="open_port",
        value=str(port) if isinstance(port, int) else "unknown",
        last_seen=parse_iso_datetime(opt_str(banner, "timestamp")),
        attributes=attributes,
    )


def _certificate_asset(banner: Mapping[str, Any]) -> ExposureAsset | None:
    ssl = banner.get("ssl")
    cert = ssl.get("cert") if isinstance(ssl, Mapping) else None
    if not isinstance(cert, Mapping):
        return None

    subject = cert.get("subject")
    subject_cn = opt_str(subject, "CN") if isinstance(subject, Mapping) else None
    issuer = cert.get("issuer")
    issuer_cn = opt_str(issuer, "CN") if isinstance(issuer, Mapping) else None
    fingerprint = cert.get("fingerprint")
    fingerprint_sha256 = (
        opt_str(fingerprint, "sha256") if isinstance(fingerprint, Mapping) else None
    )

    attributes: dict[str, Any] = {}
    if issuer_cn:
        attributes["issuer"] = issuer_cn
    expires = opt_str(cert, "expires")
    if expires:
        attributes["expires"] = expires
    if fingerprint_sha256:
        attributes["fingerprint_sha256"] = fingerprint_sha256

    return ExposureAsset(
        asset_type="certificate",
        value=subject_cn or fingerprint_sha256 or "certificate",
        attributes=attributes,
    )


def _banner_evidence(banner: Mapping[str, Any]) -> list[ExposureEvidence]:
    http = banner.get("http")
    if not isinstance(http, Mapping):
        return []
    title = opt_str(http, "title")
    if not title:
        return []
    port = banner.get("port")
    return [ExposureEvidence(type="http_title", summary=f"Port {port}: {title}", value=title)]


def _vuln_ids(value: Any) -> list[str]:
    """Shodan reports host-level ``vulns`` as either a list of CVE ids or a dict keyed by them."""
    if isinstance(value, Mapping):
        return sorted(str(key) for key in value)
    if isinstance(value, list):
        return sorted({str(item) for item in value if isinstance(item, str)})
    return []


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
