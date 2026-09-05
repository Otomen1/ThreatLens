"""VirusTotal indicator enrichment provider."""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from ..entities.models import Entity
from ..entities.types import EntityType
from .base import IntelligenceProvider
from .http import HttpClient, ProviderNetworkError, ProviderTimeout
from .models import ProviderMetadata
from .results import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    Reference,
    Reputation,
    ReputationLevel,
    ResultStatus,
)
from .types import ProviderAuthType, ProviderCapability

_NAME = "virustotal"
_DISPLAY = "VirusTotal"
_KEY_ENV = "VIRUSTOTAL_API_KEY"
_BASE = "https://www.virustotal.com/api/v3"
_SUPPORTED = frozenset(
    {
        EntityType.IPV4,
        EntityType.IPV6,
        EntityType.DOMAIN,
        EntityType.URL,
        EntityType.MD5,
        EntityType.SHA1,
        EntityType.SHA256,
    }
)
_PATH_TYPES = {
    EntityType.IPV4: "ip_addresses",
    EntityType.IPV6: "ip_addresses",
    EntityType.DOMAIN: "domains",
    EntityType.URL: "urls",
    EntityType.MD5: "files",
    EntityType.SHA1: "files",
    EntityType.SHA256: "files",
}


class VirusTotalProvider(IntelligenceProvider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        http_client: HttpClient | None = None,
        base_url: str | None = None,
        enabled: bool = True,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.getenv(_KEY_ENV)
        self._base = (base_url or os.getenv("VIRUSTOTAL_BASE_URL") or _BASE).rstrip("/")
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
                    ProviderCapability.MALWARE_ANALYSIS,
                    ProviderCapability.THREAT_CONTEXT,
                }
            ),
            priority=50,
            auth_type=ProviderAuthType.API_KEY,
            enabled=self._enabled,
        )

    async def search(self, entity: Entity) -> IntelligenceResult:
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)
        if not self._api_key:
            return self._fail(
                entity,
                ResultStatus.UNAUTHORIZED,
                "VirusTotal API key not configured; set VIRUSTOTAL_API_KEY",
            )
        try:
            response = await self._http.get(
                f"{self._base}/{_PATH_TYPES[entity.type]}/{quote(entity.value, safe='')}",
                headers={"x-apikey": self._api_key, "Accept": "application/json"},
            )
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ResultStatus.TIMEOUT,
                "VirusTotal request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "Could not reach VirusTotal",
                retryable=True,
                detail=str(exc),
            )
        if response.status_code in (401, 403):
            return self._fail(entity, ResultStatus.UNAUTHORIZED, "VirusTotal rejected the API key")
        if response.status_code == 404:
            return self._not_found(entity.type, entity.value)
        if response.status_code == 429:
            return self._fail(
                entity, ResultStatus.RATE_LIMITED, "VirusTotal rate limit reached", retryable=True
            )
        if response.status_code >= 400:
            return self._fail(
                entity, ResultStatus.ERROR, f"VirusTotal returned HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            return self._fail(
                entity, ResultStatus.ERROR, "VirusTotal returned malformed JSON", detail=str(exc)
            )
        return self._build(entity, payload)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        raise NotImplementedError("VirusTotal normalization requires the original entity")

    def _build(self, entity: Entity, payload: Mapping[str, Any]) -> IntelligenceResult:
        data = payload.get("data") if isinstance(payload, Mapping) else None
        attrs = data.get("attributes", {}) if isinstance(data, Mapping) else {}
        stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, Mapping) else {}
        malicious = stats.get("malicious", 0) if isinstance(stats, Mapping) else 0
        suspicious = stats.get("suspicious", 0) if isinstance(stats, Mapping) else 0
        total = (
            sum(v for v in stats.values() if isinstance(v, int))
            if isinstance(stats, Mapping)
            else 0
        )
        score = round((malicious + suspicious * 0.5) / total * 100) if total else 0
        level = (
            ReputationLevel.MALICIOUS
            if malicious
            else ReputationLevel.SUSPICIOUS
            if suspicious
            else ReputationLevel.UNKNOWN
        )
        evidence = [
            Evidence(
                type=EvidenceType.OTHER,
                summary="VirusTotal malicious detections",
                value=str(malicious),
            ),
            Evidence(
                type=EvidenceType.OTHER,
                summary="VirusTotal suspicious detections",
                value=str(suspicious),
            ),
        ]
        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity.type,
            entity_value=entity.value,
            status=ResultStatus.OK,
            reputation=Reputation(
                level=level,
                score=score,
                summary=f"VirusTotal: {malicious} malicious / {total} engines",
            ),
            evidence=evidence,
            references=[
                Reference(
                    title="VirusTotal report",
                    url=(
                        "https://www.virustotal.com/gui/"
                        f"{_PATH_TYPES[entity.type][:-1]}/{quote(entity.value, safe='')}"
                    ),
                )
            ],
            fetched_at=datetime.now(UTC),
            metadata={
                "malicious": str(malicious),
                "suspicious": str(suspicious),
                "engines": str(total),
            },
        )
