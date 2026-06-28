"""The AI explanation service — config-aware, never-failing entry point.

Resolves the configured provider once and exposes a single ``explain`` method.
When AI is disabled it returns a structured ``disabled`` response without
constructing a provider; when no provider is configured (unknown name) it returns
``unavailable``. The provider itself returns ``unavailable`` / ``error`` on
runtime failures. The service therefore never raises and never fails an
investigation.
"""

from __future__ import annotations

from ..reasoning import InvestigationSummary
from .config import AISettings
from .models import AIExplanation
from .ollama import OllamaProvider
from .provider import AIProvider


class AIExplanationService:
    """Wraps a configured (or absent) AI provider behind a safe ``explain``."""

    def __init__(self, settings: AISettings, provider: AIProvider | None) -> None:
        self._settings = settings
        self._provider = provider

    @property
    def enabled(self) -> bool:
        return self._settings.enabled and self._provider is not None

    async def explain(self, summary: InvestigationSummary) -> AIExplanation:
        """Return an explanation (or a structured disabled/unavailable response)."""
        if not self._settings.enabled:
            return AIExplanation.disabled()
        if self._provider is None:
            return AIExplanation.unavailable(
                provider=self._settings.provider,
                model=None,
                reason=f"provider {self._settings.provider!r} is not configured",
            )
        return await self._provider.explain(summary)


def build_ai_provider(settings: AISettings) -> AIProvider | None:
    """Construct the configured provider, or ``None`` if disabled/unknown.

    Only ``ollama`` is implemented in this phase. Future providers (openai,
    anthropic, gemini, azure_openai) plug in here without changing callers.
    """
    if not settings.enabled:
        return None
    if settings.provider == "ollama":
        return OllamaProvider(
            url=settings.ollama_url,
            model=settings.ollama_model,
            timeout=settings.timeout,
        )
    return None


def build_ai_service(settings: AISettings | None = None) -> AIExplanationService:
    """Build the service from settings (environment by default)."""
    resolved = settings or AISettings.from_env()
    return AIExplanationService(resolved, build_ai_provider(resolved))
