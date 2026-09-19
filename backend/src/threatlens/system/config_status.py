"""Configuration status for the dashboard (Section 3).

Reuses ``api/health.py``'s existing, already-tested "is this provider
configured" checks — this module adds no new credential-detection logic. It
only reshapes their output and adds the AI provider/model. No credential
value, token, or URL is ever read or returned here; only booleans and
provider/model *names*.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from ..ai.config import AISettings
from .schemas import AIConfigStatus, ConfigItem, ConfigStatusResponse


def _now() -> str:
    return datetime.now(UTC).isoformat()


def build_config_status() -> ConfigStatusResponse:
    from ..api.health import knowledge_health, providers_health

    ti = providers_health()
    kb = knowledge_health()
    ai_settings = AISettings.from_env()
    from ..identity.runtime import config as identity_config
    from ..identity.runtime import registry as identity_registry

    return ConfigStatusResponse(
        threat_intelligence=[
            ConfigItem(
                name=item.name,
                display_name=item.display_name,
                configured=item.configured,
                enabled=item.enabled,
            )
            for item in ti.providers
        ],
        knowledge=[
            ConfigItem(
                name=item.name,
                display_name=item.display_name,
                configured=item.loaded,
                enabled=item.enabled,
            )
            for item in kb.datasets
        ],
        identity=[
            ConfigItem(
                name=provider.name,
                display_name=provider.metadata.display_name,
                configured=bool(os.getenv("HIBP_API_KEY", "").strip())
                if provider.name == "hibp"
                else False,
                enabled=identity_config.enabled and provider.enabled,
            )
            for provider in identity_registry.providers
        ],
        ai=AIConfigStatus(
            provider=ai_settings.provider,
            enabled=ai_settings.enabled,
            model=ai_settings.ollama_model if ai_settings.enabled else None,
        ),
        timestamp=_now(),
    )
