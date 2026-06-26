"""URLhaus intelligence provider (abuse.ch).

Looks up malicious URLs (``/url/``) and hosts/domains (``/host/``) against
URLhaus and normalizes the response into the canonical :class:`IntelligenceResult`.
Like every provider it only retrieves and normalizes — it never scores, decides a
final verdict, or touches other providers.

Auth: abuse.ch issues one free Auth-Key (https://auth.abuse.ch) shared across its
services. The key is read from ``URLHAUS_AUTH_KEY`` or the shared
``ABUSE_CH_AUTH_KEY`` and sent as the ``Auth-Key`` header; without it the provider
still runs and degrades gracefully (an auth rejection becomes ``UNAUTHORIZED``).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from ..entities.models import Entity
from ..entities.types import EntityType
from ._normalize import opt_str, parse_datetime, str_list
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

_NAME = "urlhaus"
_DISPLAY = "URLhaus"
_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
_SUPPORTED = frozenset({EntityType.URL, EntityType.DOMAIN})
_AUTH_ENV = "URLHAUS_AUTH_KEY"
_SHARED_AUTH_ENV = "ABUSE_CH_AUTH_KEY"

_Builder = Callable[[EntityType, str, Mapping[str, Any]], IntelligenceResult]


class UrlhausProvider(IntelligenceProvider):
    """Looks up malicious URLs and hosts against URLhaus."""

    def __init__(
        self,
        *,
        auth_key: str | None = None,
        http_client: HttpClient | None = None,
        enabled: bool = True,
    ) -> None:
        self._auth_key = (
            auth_key
            if auth_key is not None
            else os.getenv(_AUTH_ENV) or os.getenv(_SHARED_AUTH_ENV)
        )
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
                    ProviderCapability.URL_ANALYSIS,
                    ProviderCapability.BLOCKLIST,
                    ProviderCapability.MALWARE_ANALYSIS,
                }
            ),
            priority=25,
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

        is_url = entity.type is EntityType.URL
        endpoint = _URL_ENDPOINT if is_url else _HOST_ENDPOINT
        field = "url" if is_url else "host"

        try:
            response = await self._http.post_form(
                endpoint,
                data={field: entity.value},
                headers=self._auth_headers(),
            )
        except ProviderTimeout as exc:
            return self._fail(
                entity,
                ResultStatus.TIMEOUT,
                "URLhaus request timed out",
                retryable=True,
                detail=str(exc),
            )
        except ProviderNetworkError as exc:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "Could not reach URLhaus",
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
                entity, ResultStatus.ERROR, "URLhaus returned malformed JSON", detail=str(exc)
            )

        if is_url:
            return self._from_payload(entity, payload, self._build_url, "invalid_url")
        return self._from_payload(entity, payload, self._build_host, "invalid_host")

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map an OK URLhaus payload into a canonical result.

        Dispatches by shape: a ``urls`` array is a host lookup, otherwise a URL
        lookup. Entity identity is derived from the payload.
        """
        payload: Mapping[str, Any] = raw
        if "urls" in payload:
            return self._build_host(
                EntityType.DOMAIN, opt_str(payload, "host") or "unknown", payload
            )
        return self._build_url(EntityType.URL, opt_str(payload, "url") or "unknown", payload)

    # --- internals -------------------------------------------------------- #

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._auth_key:
            headers["Auth-Key"] = self._auth_key
        return headers

    def _map_http_status(self, entity: Entity, code: int) -> IntelligenceResult | None:
        if code in (401, 403):
            return self._fail(
                entity,
                ResultStatus.UNAUTHORIZED,
                "URLhaus rejected the request; set URLHAUS_AUTH_KEY or "
                "ABUSE_CH_AUTH_KEY (free key at https://auth.abuse.ch)",
            )
        if code == 429:
            return self._fail(
                entity, ResultStatus.RATE_LIMITED, "URLhaus rate limit reached", retryable=True
            )
        if code >= 400:
            return self._fail(entity, ResultStatus.ERROR, f"URLhaus returned HTTP {code}")
        return None

    def _from_payload(
        self, entity: Entity, payload: Any, builder: _Builder, invalid_status: str
    ) -> IntelligenceResult:
        status = (
            str(payload.get("query_status", "")).lower() if isinstance(payload, Mapping) else ""
        )
        if status == "ok":
            return builder(entity.type, entity.value, payload)
        if status == "no_results":
            return self._not_found(entity.type, entity.value)
        if status == invalid_status:
            label = "URL" if invalid_status == "invalid_url" else "host"
            return IntelligenceResult.failure(
                provider=_NAME,
                provider_display_name=_DISPLAY,
                entity_type=entity.type,
                entity_value=entity.value,
                message=f"URLhaus reported the {label} as invalid",
            )
        return IntelligenceResult.failure(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity.type,
            entity_value=entity.value,
            message=f"URLhaus returned an unexpected status: {status or 'unknown'!r}",
        )

    def _build_url(
        self, entity_type: EntityType, entity_value: str, payload: Mapping[str, Any]
    ) -> IntelligenceResult:
        url_status = opt_str(payload, "url_status")
        threat = opt_str(payload, "threat")
        host = opt_str(payload, "host")
        date_added = opt_str(payload, "date_added")
        reporter = opt_str(payload, "reporter")
        tags = str_list(payload, "tags")
        payloads = [p for p in _as_list(payload.get("payloads")) if isinstance(p, Mapping)]
        families = _unique(opt_str(p, "signature") for p in payloads)

        evidence: list[Evidence] = []
        _add(evidence, EvidenceType.OTHER, "URL status", url_status)
        _add(evidence, EvidenceType.CATEGORY, "Threat type", threat)
        _add(evidence, EvidenceType.OTHER, "Host", host)
        for family in families:
            evidence.append(
                Evidence(
                    type=EvidenceType.MALWARE_FAMILY,
                    summary=f"Payload family: {family}",
                    value=family,
                )
            )
        if date_added:
            evidence.append(
                Evidence(
                    type=EvidenceType.FIRST_SEEN,
                    summary=f"First seen on URLhaus: {date_added}",
                    value=date_added,
                    observed_at=parse_datetime(date_added),
                )
            )
        _add(evidence, EvidenceType.OTHER, "Reported by", reporter)
        evidence.extend(
            Evidence(type=EvidenceType.TAG, summary=f"Tag: {tag}", value=tag) for tag in tags
        )

        relationships: list[Relationship] = []
        if host:
            relationships.append(
                _relationship(RelationshipType.RELATED_TO, RelationshipTargetType.INDICATOR, host)
            )
        for sample in payloads:
            sha256 = opt_str(sample, "response_sha256")
            if sha256:
                relationships.append(
                    _relationship(RelationshipType.DROPS, RelationshipTargetType.INDICATOR, sha256)
                )
        relationships.extend(
            _relationship(RelationshipType.INDICATES, RelationshipTargetType.MALWARE_FAMILY, family)
            for family in families
        )

        metadata = _metadata(payload, ("url_status", "threat", "host", "date_added", "reporter"))
        suffix = f" ({threat})" if threat else ""
        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.OK,
            reputation=Reputation(
                level=ReputationLevel.MALICIOUS,
                summary=f"Malicious URL{suffix} listed in URLhaus",
            ),
            evidence=evidence,
            relationships=relationships,
            references=self._references(payload, "URLhaus URL entry"),
            tags=tags,
            fetched_at=datetime.now(UTC),
            metadata=metadata,
        )

    def _build_host(
        self, entity_type: EntityType, entity_value: str, payload: Mapping[str, Any]
    ) -> IntelligenceResult:
        url_count = opt_str(payload, "url_count")
        firstseen = opt_str(payload, "firstseen")
        urls = [u for u in _as_list(payload.get("urls")) if isinstance(u, Mapping)]
        threats = _unique(opt_str(u, "threat") for u in urls)
        tags = _unique(tag for u in urls for tag in str_list(u, "tags"))

        evidence: list[Evidence] = []
        _add(evidence, EvidenceType.OTHER, "Malicious URLs observed", url_count)
        if firstseen:
            evidence.append(
                Evidence(
                    type=EvidenceType.FIRST_SEEN,
                    summary=f"First seen on URLhaus: {firstseen}",
                    value=firstseen,
                    observed_at=parse_datetime(firstseen),
                )
            )
        evidence.extend(
            Evidence(type=EvidenceType.CATEGORY, summary=f"Threat type: {t}", value=t)
            for t in threats
        )
        evidence.extend(
            Evidence(type=EvidenceType.TAG, summary=f"Tag: {tag}", value=tag) for tag in tags
        )

        relationships = [
            _relationship(RelationshipType.RELATED_TO, RelationshipTargetType.INDICATOR, url)
            for u in urls
            if (url := opt_str(u, "url"))
        ]

        count_text = f"{url_count} malicious URL(s)" if url_count else "malicious URLs"
        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.OK,
            reputation=Reputation(
                level=ReputationLevel.MALICIOUS,
                summary=f"Host serving {count_text} listed in URLhaus",
            ),
            evidence=evidence,
            relationships=relationships,
            references=self._references(payload, "URLhaus host entry"),
            tags=tags,
            fetched_at=datetime.now(UTC),
            metadata=_metadata(payload, ("url_count", "firstseen")),
        )

    def _references(self, payload: Mapping[str, Any], title: str) -> list[Reference]:
        ref = opt_str(payload, "urlhaus_reference")
        return [Reference(title=title, url=ref)] if ref else []

    def _not_found(self, entity_type: EntityType, entity_value: str) -> IntelligenceResult:
        return IntelligenceResult.not_found(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
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


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _unique(values: Any) -> list[str]:
    """Stripped, de-duplicated (case-insensitive), order-preserving strings."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        text = str(value).strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _add(evidence: list[Evidence], etype: EvidenceType, label: str, value: str | None) -> None:
    if value:
        evidence.append(Evidence(type=etype, summary=f"{label}: {value}", value=value))


def _relationship(
    verb: RelationshipType, target_type: RelationshipTargetType, target_value: str
) -> Relationship:
    return Relationship(relationship=verb, target_type=target_type, target_value=target_value)


def _metadata(payload: Mapping[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in keys:
        value = opt_str(payload, key)
        if value:
            metadata[key] = value
    return metadata
