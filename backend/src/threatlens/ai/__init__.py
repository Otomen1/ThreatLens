"""The AI explanation layer (Phase 3.2) — a downstream, optional consumer.

This package explains a completed, deterministic investigation. It is strictly
downstream of the Reasoning Engine: its only input is an
:class:`~threatlens.reasoning.InvestigationSummary`, and it can never influence
findings, confidence, severity, priority, or recommendations. AI is off by
default; with no provider running, ThreatLens behaves identically (explanations
come back ``disabled``/``unavailable``, never an error).

``OllamaProvider`` is the first provider; the :class:`AIProvider` interface lets
future providers (OpenAI, Anthropic, Gemini, Azure OpenAI) plug in unchanged.
"""

from __future__ import annotations

from .config import AISettings
from .models import (
    AIExplanation,
    AIStatus,
    FindingExplanation,
    RecommendationExplanation,
)
from .ollama import OllamaProvider
from .prompt import Prompt, PromptBuilder
from .provider import AIProvider
from .service import AIExplanationService, build_ai_provider, build_ai_service

__all__ = [
    "AIExplanation",
    "AIExplanationService",
    "AIProvider",
    "AISettings",
    "AIStatus",
    "FindingExplanation",
    "OllamaProvider",
    "Prompt",
    "PromptBuilder",
    "RecommendationExplanation",
    "build_ai_provider",
    "build_ai_service",
]
