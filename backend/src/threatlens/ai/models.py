"""Output models for the AI explanation layer (Phase 3.2).

These are the *only* things the AI produces. There is deliberately no field for
severity, confidence, priority, or recommendation content: the AI explains the
deterministic :class:`~threatlens.reasoning.InvestigationSummary`; it cannot,
structurally, alter it. Every explanation references an existing id/key from the
summary it was given (grounding is enforced in code, not just requested in the
prompt — see :mod:`.ollama`).

``disabled`` / ``unavailable`` / ``timeout`` / ``invalid_response`` / ``error``
are all first-class, structured results — the layer never raises and never fails
an investigation. Each maps to a friendly, non-alarming message; raw exception
text is logged server-side, never surfaced to the analyst.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AIStatus(StrEnum):
    """Outcome of an explanation request (never an exception)."""

    OK = "ok"
    DISABLED = "disabled"  # AI_ENABLED is false
    UNAVAILABLE = "unavailable"  # provider unreachable / not configured
    TIMEOUT = "timeout"  # provider did not respond in time
    INVALID_RESPONSE = "invalid_response"  # unparseable / schema-invalid output
    ERROR = "error"  # provider returned an error (e.g. HTTP 5xx / internal)


class FindingExplanation(BaseModel):
    """A plain-language explanation of one finding, bound to its stable id."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(min_length=1)
    explanation: str = Field(min_length=1)


class RecommendationExplanation(BaseModel):
    """An explanation of one recommendation, bound to its (action, target)."""

    model_config = ConfigDict(frozen=True)

    action: str = Field(min_length=1)
    target_value: str = Field(min_length=1)
    explanation: str = Field(min_length=1)


class AIExplanation(BaseModel):
    """The AI's narration of an investigation — additive, downstream, optional."""

    model_config = ConfigDict(frozen=True)

    status: AIStatus
    provider: str
    model: str | None = None
    # Human-facing status line (used for disabled/unavailable/error; "" when OK).
    message: str = ""
    executive_summary: str = ""
    technical_summary: str = ""
    finding_explanations: list[FindingExplanation] = Field(default_factory=list)
    recommendation_explanations: list[RecommendationExplanation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @classmethod
    def disabled(cls) -> AIExplanation:
        """The structured response when AI is turned off."""
        return cls(
            status=AIStatus.DISABLED,
            provider="none",
            message="AI explanation is disabled. Set AI_ENABLED=true to enable it.",
        )

    @classmethod
    def unavailable(cls, *, provider: str, model: str | None) -> AIExplanation:
        """The structured response when the provider cannot be reached."""
        return cls(
            status=AIStatus.UNAVAILABLE,
            provider=provider,
            model=model,
            message="AI explanation is currently unavailable; the investigation is unaffected.",
        )

    @classmethod
    def timeout(cls, *, provider: str, model: str | None) -> AIExplanation:
        """The structured response when the provider did not respond in time."""
        return cls(
            status=AIStatus.TIMEOUT,
            provider=provider,
            model=model,
            message="The AI provider timed out; the investigation is unaffected.",
        )

    @classmethod
    def invalid_response(cls, *, provider: str, model: str | None) -> AIExplanation:
        """The structured response when the provider's output was unusable."""
        return cls(
            status=AIStatus.INVALID_RESPONSE,
            provider=provider,
            model=model,
            message=(
                "The AI provider returned an unusable response; the investigation is unaffected."
            ),
        )

    @classmethod
    def error(cls, *, provider: str, model: str | None) -> AIExplanation:
        """The structured response when the provider returned an error."""
        return cls(
            status=AIStatus.ERROR,
            provider=provider,
            model=model,
            message="The AI provider reported an error; the investigation is unaffected.",
        )
