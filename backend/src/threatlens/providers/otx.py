"""AlienVault OTX intelligence provider.

Enriches IPs, domains, URLs, and file hashes with community threat intelligence
from OTX's ``/indicators/.../general`` endpoint. OTX's distinctive value is its
*pulses* — curated threat reports that tie an indicator to malware families,
threat actors, MITRE techniques, tags, and references. The provider extracts
those relationships and normalizes them into the canonical
:class:`IntelligenceResult`; it never scores or decides a verdict.

Auth: an OTX API key (https://otx.alienvault.com) read from ``OTX_API_KEY`` and
sent as ``X-OTX-API-KEY``. The key is optional — without it the provider runs in
anonymous mode and degrades gracefully (an auth rejection becomes
``UNAUTHORIZED``); a missing key never crashes the request.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

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

_NAME = "otx"
_DISPLAY = "AlienVault OTX"
_BASE = "https://otx.alienvault.com/api/v1/indicators"
_API_KEY_ENV = "OTX_API_KEY"
_MAX_PULSES = 10  # cap pulse-name evidence; metadata is aggregated across all
_MAX_REFERENCES = 20

# Entity type -> OTX indicator-type path segment.
_OTX_TYPE: dict[EntityType, str] = {
    EntityType.IPV4: "IPv4",
    EntityType.IPV6: "IPv6",
    EntityType.DOMAIN: "domain",
    EntityType.URL: "url",
    EntityType.MD5: "file",
    EntityType.SHA1: "file",
    EntityType.SHA256: "file",
}
_SUPPORTED = frozenset(_OTX_TYPE)


class OTXProvider(IntelligenceProvider):
    """Looks up indicators against AlienVault OTX pulses."""

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
                    ProviderCapability.THREAT_CONTEXT,
                    ProviderCapability.REPUTATION,
                    ProviderCapability.MALWARE_ANALYSIS,
                }
            ),
            priority=40,
            auth_type=ProviderAuthType.API_KEY,
            enabled=self._enabled,
        )

    async def search(self, entity: Entity) -> IntelligenceResult:
        """Look up ``entity`` and return a canonical result (never raises)."""
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)

        otx_type = _OTX_TYPE[entity.type]
        url = f"{_BASE}/{otx_type}/{quote(entity.value, safe='')}/general"
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key

        try:
            response = await self._http.get(url, headers=headers)
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ResultStatus.TIMEOUT,
                "OTX request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity, ResultStatus.ERROR, "Could not reach OTX", retryable=True, detail=str(exc)
            )

        http_failure = self._map_http_status(entity, response.status_code)
        if http_failure is not None:
            return http_failure

        try:
            payload = response.json()
        except ValueError as exc:
            return self._fail(
                entity, ResultStatus.ERROR, "OTX returned malformed JSON", detail=str(exc)
            )

        return self._build(entity.type, entity.value, payload)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map an OTX ``general`` payload into a canonical result.

        Entity identity is derived from the payload's ``indicator``/``type``.
        """
        payload: Mapping[str, Any] = raw
        value = opt_str(payload, "indicator") or "unknown"
        return self._build(_entity_type(opt_str(payload, "type"), value), value, payload)

    # --- internals -------------------------------------------------------- #

    def _map_http_status(self, entity: Entity, code: int) -> IntelligenceResult | None:
        if code in (401, 403):
            return self._fail(
                entity,
                ResultStatus.UNAUTHORIZED,
                "OTX rejected the request; set OTX_API_KEY (free key at "
                "https://otx.alienvault.com)",
            )
        if code == 429:
            return self._fail(
                entity, ResultStatus.RATE_LIMITED, "OTX rate limit reached", retryable=True
            )
        if code == 404:
            return self._not_found(entity.type, entity.value)
        if code >= 400:
            return self._fail(entity, ResultStatus.ERROR, f"OTX returned HTTP {code}")
        return None

    def _build(
        self, entity_type: EntityType, entity_value: str, payload: Any
    ) -> IntelligenceResult:
        pulse_info = payload.get("pulse_info") if isinstance(payload, Mapping) else None
        raw_pulses = pulse_info.get("pulses") if isinstance(pulse_info, Mapping) else None
        pulses = [p for p in _as_list(raw_pulses) if isinstance(p, Mapping)]
        if not pulses:
            # OTX knows the indicator but no pulse references it: no threat intel.
            return self._not_found(entity_type, entity_value)

        families = _unique(
            name for p in pulses for name in _names(p.get("malware_families"), "display_name")
        )
        actors = _unique(opt_str(p, "adversary") for p in pulses)
        techniques = _unique(tid for p in pulses for tid in _names(p.get("attack_ids"), "id"))
        tags = _unique(tag for p in pulses for tag in str_list(p, "tags"))
        references = _unique(ref for p in pulses for ref in str_list(p, "references"))
        created = [c for p in pulses if (c := opt_str(p, "created"))]
        modified = [m for p in pulses if (m := opt_str(p, "modified"))]
        first_seen = min(created) if created else None
        last_seen = max(modified) if modified else None

        evidence: list[Evidence] = [
            Evidence(
                type=EvidenceType.OTHER,
                summary=f"Referenced in {len(pulses)} OTX pulse(s)",
                value=str(len(pulses)),
            )
        ]
        evidence.extend(
            Evidence(type=EvidenceType.PULSE_MATCH, summary=f"OTX pulse: {name}", value=name)
            for pulse in pulses[:_MAX_PULSES]
            if (name := opt_str(pulse, "name"))
        )
        evidence.extend(
            Evidence(type=EvidenceType.MALWARE_FAMILY, summary=f"Malware family: {f}", value=f)
            for f in families
        )
        evidence.extend(
            Evidence(type=EvidenceType.OTHER, summary=f"Threat actor: {a}", value=a) for a in actors
        )
        evidence.extend(
            Evidence(type=EvidenceType.OTHER, summary=f"MITRE technique: {t}", value=t)
            for t in techniques
        )
        _add_seen(evidence, EvidenceType.FIRST_SEEN, "First seen in OTX", first_seen)
        _add_seen(evidence, EvidenceType.LAST_SEEN, "Last seen in OTX", last_seen)
        evidence.extend(
            Evidence(type=EvidenceType.TAG, summary=f"Tag: {tag}", value=tag) for tag in tags
        )

        relationships: list[Relationship] = []
        relationships.extend(
            _relationship(RelationshipType.INDICATES, RelationshipTargetType.MALWARE_FAMILY, f)
            for f in families
        )
        relationships.extend(
            _relationship(RelationshipType.ATTRIBUTED_TO, RelationshipTargetType.THREAT_ACTOR, a)
            for a in actors
        )
        relationships.extend(
            _relationship(RelationshipType.USES, RelationshipTargetType.ATTACK_PATTERN, t)
            for t in techniques
        )

        metadata: dict[str, Any] = {"pulse_count": len(pulses)}
        if first_seen:
            metadata["first_seen"] = first_seen
        if last_seen:
            metadata["last_seen"] = last_seen

        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.OK,
            reputation=Reputation(
                level=ReputationLevel.SUSPICIOUS,
                summary=f"Referenced in {len(pulses)} OTX pulse(s)",
            ),
            evidence=evidence,
            relationships=relationships,
            references=[
                Reference(title="OTX pulse reference", url=url)
                for url in references[:_MAX_REFERENCES]
            ],
            tags=tags,
            fetched_at=datetime.now(UTC),
            metadata=metadata,
        )


def _entity_type(type_str: str | None, value: str) -> EntityType:
    """Best-effort map an OTX indicator ``type`` back to an EntityType."""
    text = (type_str or "").lower()
    if "ipv4" in text:
        return EntityType.IPV4
    if "ipv6" in text:
        return EntityType.IPV6
    if "url" in text:
        return EntityType.URL
    if "domain" in text or "hostname" in text:
        return EntityType.DOMAIN
    lengths = {32: EntityType.MD5, 40: EntityType.SHA1, 64: EntityType.SHA256}
    return lengths.get(len(value), EntityType.SHA256)


def _names(items: Any, key: str) -> list[str]:
    """Extract display names from a list of dicts (by ``key``) or plain strings."""
    out: list[str] = []
    for item in _as_list(items):
        value = opt_str(item, key) if isinstance(item, Mapping) else _coerce(item)
        if value:
            out.append(value)
    return out


def _coerce(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _unique(values: Any) -> list[str]:
    """Stripped, case-insensitively de-duplicated, order-preserving strings."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _coerce(value)
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


def _add_seen(evidence: list[Evidence], etype: EvidenceType, label: str, value: str | None) -> None:
    if value:
        evidence.append(
            Evidence(
                type=etype,
                summary=f"{label}: {value}",
                value=value,
                observed_at=parse_iso_datetime(value),
            )
        )


def _relationship(
    verb: RelationshipType, target_type: RelationshipTargetType, target_value: str
) -> Relationship:
    return Relationship(relationship=verb, target_type=target_type, target_value=target_value)
