"""AbuseIPDB intelligence provider.

Enriches IPv4/IPv6 indicators with IP reputation and abuse intelligence from
AbuseIPDB's ``/check`` endpoint, normalized into the canonical
:class:`IntelligenceResult`. It only retrieves and normalizes — it never scores,
decides a final verdict, or touches other providers.

Auth: a free API key from https://www.abuseipdb.com, read from
``ABUSEIPDB_API_KEY`` and sent as the ``Key`` header. A missing key yields a
structured ``UNAUTHORIZED`` result rather than an exception. Private, reserved,
and otherwise non-global IPs short-circuit to ``NOT_FOUND`` without a request.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ..entities.models import Entity
from ..entities.types import EntityType
from ._normalize import opt_str, parse_iso_datetime, str_list
from .base import IntelligenceProvider
from .http import HttpClient, ProviderNetworkError, ProviderTimeout
from .models import ProviderMetadata
from .results import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    Reference,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    Reputation,
    ReputationLevel,
    ResultStatus,
)
from .types import ProviderAuthType, ProviderCapability

_NAME = "abuseipdb"
_DISPLAY = "AbuseIPDB"
_API_URL = "https://api.abuseipdb.com/api/v2/check"
_REPORT_URL = "https://www.abuseipdb.com/check/{ip}"
_SUPPORTED = frozenset({EntityType.IPV4, EntityType.IPV6})
_API_KEY_ENV = "ABUSEIPDB_API_KEY"
_MAX_AGE_DAYS = "90"

# AbuseIPDB's fixed report-category vocabulary (numeric id -> name).
_CATEGORY_NAMES: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBProvider(IntelligenceProvider):
    """Looks up IP reputation against AbuseIPDB."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        http_client: HttpClient | None = None,
        enabled: bool = True,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.getenv(_API_KEY_ENV)
        self._http = http_client or HttpClient()
        self._enabled = enabled

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            name=_NAME,
            display_name=_DISPLAY,
            supported_entity_types=_SUPPORTED,
            capabilities=frozenset(
                {
                    ProviderCapability.REPUTATION,
                    ProviderCapability.GEOLOCATION,
                    ProviderCapability.BLOCKLIST,
                }
            ),
            priority=30,
            auth_type=ProviderAuthType.API_KEY,
            enabled=self._enabled,
        )

    async def search(self, entity: Entity) -> IntelligenceResult:
        """Look up ``entity`` and return a canonical result (never raises)."""
        if not self.supports(entity.type):
            return IntelligenceResult.unsupported(
                provider=_NAME,
                provider_display_name=_DISPLAY,
                entity_type=entity.type,
                entity_value=entity.value,
            )

        try:
            ip = ipaddress.ip_address(entity.value)
        except ValueError:
            return self._fail(
                entity, ResultStatus.ERROR, "AbuseIPDB received an invalid IP address"
            )

        if not ip.is_global:
            # Private/reserved/loopback/link-local: no public reputation applies.
            return IntelligenceResult.not_found(
                provider=_NAME,
                provider_display_name=_DISPLAY,
                entity_type=entity.type,
                entity_value=entity.value,
            )

        if not self._api_key:
            return self._fail(
                entity,
                ResultStatus.UNAUTHORIZED,
                "AbuseIPDB API key not configured; set ABUSEIPDB_API_KEY "
                "(free key at https://www.abuseipdb.com)",
            )

        try:
            response = await self._http.get(
                _API_URL,
                params={
                    "ipAddress": entity.value,
                    "maxAgeInDays": _MAX_AGE_DAYS,
                    "verbose": "",
                },
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ResultStatus.TIMEOUT,
                "AbuseIPDB request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "Could not reach AbuseIPDB",
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
                entity, ResultStatus.ERROR, "AbuseIPDB returned malformed JSON", detail=str(exc)
            )

        data = payload.get("data") if isinstance(payload, Mapping) else None
        if not isinstance(data, Mapping):
            return self._fail(
                entity, ResultStatus.ERROR, "AbuseIPDB returned an unexpected response"
            )
        return self._build(entity.type, entity.value, data)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map an AbuseIPDB ``data`` object into a canonical result.

        Entity identity is derived from the record's ``ipAddress``/``ipVersion``.
        """
        data: Mapping[str, Any] = raw
        ip = opt_str(data, "ipAddress") or "unknown"
        entity_type = EntityType.IPV6 if data.get("ipVersion") == 6 else EntityType.IPV4
        return self._build(entity_type, ip, data)

    # --- internals -------------------------------------------------------- #

    def _map_http_status(self, entity: Entity, code: int) -> IntelligenceResult | None:
        if code in (401, 403):
            return self._fail(
                entity,
                ResultStatus.UNAUTHORIZED,
                "AbuseIPDB rejected the API key; check ABUSEIPDB_API_KEY",
            )
        if code == 429:
            return self._fail(
                entity, ResultStatus.RATE_LIMITED, "AbuseIPDB rate limit reached", retryable=True
            )
        if code >= 400:
            return self._fail(entity, ResultStatus.ERROR, f"AbuseIPDB returned HTTP {code}")
        return None

    def _build(
        self, entity_type: EntityType, entity_value: str, data: Mapping[str, Any]
    ) -> IntelligenceResult:
        score = data.get("abuseConfidenceScore")
        score_value = max(0, min(100, score)) if isinstance(score, int) else 0
        whitelisted = bool(data.get("isWhitelisted"))
        categories = _categories(data)

        evidence: list[Evidence] = []
        _add(evidence, EvidenceType.ABUSE_CONFIDENCE, "Abuse confidence score", f"{score_value}%")
        _add_int(evidence, "Total reports", data.get("totalReports"))
        _add_int(evidence, "Distinct reporters", data.get("numDistinctUsers"))
        last_reported = opt_str(data, "lastReportedAt")
        if last_reported:
            evidence.append(
                Evidence(
                    type=EvidenceType.LAST_SEEN,
                    summary=f"Last reported: {last_reported}",
                    value=last_reported,
                    observed_at=parse_iso_datetime(last_reported),
                )
            )
        _add(evidence, EvidenceType.OTHER, "Country", opt_str(data, "countryCode"))
        _add(evidence, EvidenceType.OTHER, "ISP", opt_str(data, "isp"))
        _add(evidence, EvidenceType.OTHER, "Domain", opt_str(data, "domain"))
        _add(evidence, EvidenceType.OTHER, "Usage type", opt_str(data, "usageType"))
        if data.get("isTor"):
            _add(evidence, EvidenceType.OTHER, "Tor exit node", "yes")
        if whitelisted:
            _add(evidence, EvidenceType.OTHER, "Whitelisted", "yes")
        evidence.extend(
            Evidence(type=EvidenceType.CATEGORY, summary=f"Reported for: {name}", value=name)
            for name in categories
        )

        relationships: list[Relationship] = []
        domain = opt_str(data, "domain")
        if domain:
            relationships.append(
                _relationship(RelationshipType.RELATED_TO, RelationshipTargetType.INDICATOR, domain)
            )
        relationships.extend(
            _relationship(RelationshipType.RESOLVES_TO, RelationshipTargetType.INDICATOR, hostname)
            for hostname in str_list(data, "hostnames")
        )

        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.OK,
            reputation=Reputation(
                level=_level(score_value, whitelisted=whitelisted),
                score=score_value,
                summary=f"AbuseIPDB abuse confidence: {score_value}%",
            ),
            evidence=evidence,
            relationships=relationships,
            references=[
                Reference(title="AbuseIPDB report", url=_REPORT_URL.format(ip=entity_value))
            ],
            tags=categories,
            fetched_at=datetime.now(UTC),
            metadata=_metadata(data),
        )

    def _fail(
        self,
        entity: Entity,
        status: ResultStatus,
        message: str,
        *,
        retryable: bool = False,
        detail: str | None = None,
    ) -> IntelligenceResult:
        return IntelligenceResult.failure(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity.type,
            entity_value=entity.value,
            message=message,
            status=status,
            retryable=retryable,
            detail=detail,
        )


def _level(score: int, *, whitelisted: bool) -> ReputationLevel:
    """Normalize AbuseIPDB's own abuse-confidence score into a band (not a TL score)."""
    if whitelisted:
        return ReputationLevel.BENIGN
    if score >= 75:
        return ReputationLevel.MALICIOUS
    if score >= 50:
        return ReputationLevel.LIKELY_MALICIOUS
    if score >= 25:
        return ReputationLevel.SUSPICIOUS
    if score >= 1:
        return ReputationLevel.LIKELY_BENIGN
    return ReputationLevel.UNKNOWN


def _categories(data: Mapping[str, Any]) -> list[str]:
    """Unique, sorted report-category names from a verbose AbuseIPDB response."""
    reports = data.get("reports")
    ids = sorted(
        {
            category
            for report in (reports if isinstance(reports, list) else [])
            if isinstance(report, Mapping)
            for category in (report.get("categories") or [])
            if isinstance(category, int)
        }
    )
    return [_CATEGORY_NAMES[i] for i in ids if i in _CATEGORY_NAMES]


def _metadata(data: Mapping[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in ("ipAddress", "countryCode", "isp", "domain", "usageType", "lastReportedAt"):
        value = opt_str(data, key)
        if value:
            metadata[key] = value
    for key in ("abuseConfidenceScore", "totalReports", "numDistinctUsers"):
        value = data.get(key)
        if isinstance(value, int):
            metadata[key] = value
    for key in ("isTor", "isWhitelisted", "isPublic"):
        value = data.get(key)
        if isinstance(value, bool):
            metadata[key] = value
    return metadata


def _add(evidence: list[Evidence], etype: EvidenceType, label: str, value: str | None) -> None:
    if value:
        evidence.append(Evidence(type=etype, summary=f"{label}: {value}", value=value))


def _add_int(evidence: list[Evidence], label: str, value: Any) -> None:
    if isinstance(value, int):
        evidence.append(
            Evidence(type=EvidenceType.OTHER, summary=f"{label}: {value}", value=str(value))
        )


def _relationship(
    verb: RelationshipType, target_type: RelationshipTargetType, target_value: str
) -> Relationship:
    return Relationship(relationship=verb, target_type=target_type, target_value=target_value)
