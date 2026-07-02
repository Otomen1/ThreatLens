"""The AI provider abstraction.

A provider turns an :class:`~threatlens.reasoning.InvestigationSummary` into an
:class:`~threatlens.ai.models.AIExplanation`. Its sole input is the summary — it
has no access to threat-intelligence providers, knowledge providers, aggregated
evidence, raw reputation, or API responses. New providers (OpenAI, Anthropic,
Gemini, Azure OpenAI) implement this same interface so callers never change;
``OllamaProvider`` is the only concrete provider in this phase.

``explain`` must never raise: connection failures and unusable responses are
returned as ``unavailable`` / ``error`` explanations, so an investigation always
succeeds whether or not a model is running.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..reasoning import InvestigationSummary
from .models import AIExplanation


class AIProvider(ABC):
    """Base class for downstream AI explanation providers."""

    name: ClassVar[str]

    @abstractmethod
    async def explain(self, summary: InvestigationSummary) -> AIExplanation:
        """Explain ``summary``. Implementations must never raise."""
