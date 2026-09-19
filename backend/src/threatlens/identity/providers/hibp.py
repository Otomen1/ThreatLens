"""Optional Have I Been Pwned breach lookup provider."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from ...entities.models import Entity
from ...entities.types import EntityType
from ...providers.http import HttpClient, ProviderHttpError, ProviderTimeout
from ..models import (
    IdentityAsset,
    IdentityAuthType,
    IdentityCapability,
    IdentityEvidence,
    IdentityFinding,
    IdentityProviderHealth,
    IdentityProviderMetadata,
    IdentityProviderStatus,
    IdentityReference,
    IdentityStatus,
)
from ..provider import IdentityProvider

logger = logging.getLogger(__name__)


class HibpProvider(IdentityProvider):
    def __init__(
        self,
        *,
        client: HttpClient | None = None,
        enabled: bool | None = None,
        timeout: float | None = None,
    ) -> None:
        self._api_key = os.getenv("HIBP_API_KEY", "").strip()
        env_enabled = os.getenv("HIBP_ENABLED", "true").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self._enabled = env_enabled if enabled is None else enabled
        self._base_url = os.getenv("HIBP_BASE_URL", "https://haveibeenpwned.com/api/v3").rstrip("/")
        resolved_timeout = (
            timeout if timeout is not None else float(os.getenv("HIBP_TIMEOUT", "10"))
        )
        self._client = client or HttpClient(timeout=resolved_timeout)

    @property
    def metadata(self) -> IdentityProviderMetadata:
        return IdentityProviderMetadata(
            name="hibp",
            display_name="Have I Been Pwned",
            supported_entity_types=frozenset({EntityType.EMAIL}),
            capabilities=frozenset(
                {IdentityCapability.BREACHES, IdentityCapability.CREDENTIAL_EXPOSURE}
            ),
            priority=100,
            auth_type=IdentityAuthType.API_KEY,
            enabled=self._enabled,
        )

    async def lookup(self, entity: Entity) -> IdentityFinding:
        if entity.type is not EntityType.EMAIL:
            return self._unsupported(entity.type, entity.value)
        if not self._api_key:
            return self._fail(entity, IdentityStatus.UNAUTHORIZED, "HIBP API key is not configured")
        try:
            response = await self._client.get(
                f"{self._base_url}/breachedaccount/{entity.normalized_value}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": self._api_key, "user-agent": "ThreatLens/1.2"},
            )
        except ProviderTimeout as exc:
            logger.warning("HIBP identity request timed out", exc_info=exc)
            return self._fail(
                entity,
                IdentityStatus.TIMEOUT,
                "HIBP request timed out",
                retryable=True,
            )
        except ProviderHttpError as exc:
            logger.warning("HIBP identity request failed", exc_info=exc)
            return self._fail(
                entity, IdentityStatus.ERROR, "HIBP request failed", retryable=True
            )
        if response.status_code == 404:
            return self._not_found(entity.type, entity.value)
        if response.status_code in {401, 403}:
            return self._fail(entity, IdentityStatus.UNAUTHORIZED, "HIBP rejected the API key")
        if response.status_code == 429:
            return self._fail(
                entity,
                IdentityStatus.RATE_LIMITED,
                "HIBP rate limit reached",
                retryable=True,
            )
        if response.status_code != 200:
            return self._fail(
                entity,
                IdentityStatus.ERROR,
                f"HIBP returned HTTP {response.status_code}",
                retryable=response.status_code >= 500,
            )
        try:
            breaches = response.json()
        except ValueError as exc:
            logger.warning("HIBP identity response contained invalid JSON", exc_info=exc)
            return self._fail(
                entity, IdentityStatus.ERROR, "HIBP returned invalid JSON"
            )
        if not isinstance(breaches, list):
            return self._fail(entity, IdentityStatus.ERROR, "HIBP returned an unexpected response")
        evidence = [
            IdentityEvidence(
                type="breach",
                summary=str(item.get("Name", "Known breach")),
                value=str(item.get("Title", "")) or None,
                data={
                    "domain": item.get("Domain", ""),
                    "data_classes": item.get("DataClasses", []),
                    "breach_date": item.get("BreachDate", ""),
                    "added_date": item.get("AddedDate", ""),
                    "pwn_count": item.get("PwnCount", 0),
                    "verified": item.get("IsVerified", False),
                },
            )
            for item in breaches
            if isinstance(item, dict)
        ]
        assets = [
            IdentityAsset(
                asset_type="breached_account",
                value=entity.normalized_value,
                attributes={"breach_count": len(breaches)},
            )
        ]
        return IdentityFinding(
            provider="hibp",
            provider_display_name=self.metadata.display_name,
            entity_type=entity.type,
            entity_value=entity.value,
            category=IdentityCapability.BREACHES,
            summary=f"Found in {len(breaches)} breach(es).",
            evidence=evidence,
            assets=assets,
            references=[
                IdentityReference(title="Have I Been Pwned", url="https://haveibeenpwned.com/")
            ],
            fetched_at=datetime.now(UTC),
        )

    async def normalize(self, raw: Any) -> IdentityFinding:
        raise NotImplementedError("HIBP normalizes directly in lookup")

    async def health(self) -> IdentityProviderHealth:
        if not self._enabled:
            return IdentityProviderHealth(name=self.name, status=IdentityProviderStatus.DISABLED)
        if not self._api_key:
            return IdentityProviderHealth(
                name=self.name,
                status=IdentityProviderStatus.UNAVAILABLE,
                detail="API key not configured",
            )
        return IdentityProviderHealth(name=self.name, status=IdentityProviderStatus.OPERATIONAL)

    async def configuration(self) -> dict[str, Any]:
        return {
            "enabled": self._enabled,
            "configured": bool(self._api_key),
            "base_url": self._base_url,
        }
