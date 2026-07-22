"""The Ollama provider â€” the first concrete AI explanation provider.

Calls a local/remote Ollama server's ``/api/chat`` with a deterministic prompt
(``temperature=0``, ``format=json``) built from the InvestigationSummary, then
parses, schema-validates, and **grounds** the result: any explanation that
references a finding id or recommendation not present in the summary is dropped.
The model cannot, therefore, introduce findings, evidence, or recommendations â€”
grounding is enforced in code, not merely requested in the prompt.

Every failure path returns a structured ``timeout`` / ``unavailable`` /
``invalid_response`` / ``error`` explanation; ``explain`` never raises. The
underlying reason is logged server-side for troubleshooting and never surfaced
to the analyst.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..providers.http import (
    HttpClient,
    ProviderHttpError,
    ProviderNetworkError,
    ProviderServerError,
    ProviderTimeout,
)
from ..reasoning import InvestigationSummary
from .models import AIExplanation, AIStatus, FindingExplanation, RecommendationExplanation
from .prompt import PromptBuilder
from .provider import AIProvider

logger = logging.getLogger(__name__)

_THINK_TAG = re.compile(r"<think>.*?</think>", re.DOTALL)


class _RawFindingExplanation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    finding_id: str = ""
    explanation: str = ""


class _RawRecommendationExplanation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    action: str = ""
    target_value: str = ""
    explanation: str = ""


class _RawExplanation(BaseModel):
    """Lenient view of the model's JSON before grounding."""

    model_config = ConfigDict(extra="ignore")

    executive_summary: str = ""
    technical_summary: str = ""
    finding_explanations: list[_RawFindingExplanation] = Field(default_factory=list)
    recommendation_explanations: list[_RawRecommendationExplanation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class OllamaProvider(AIProvider):
    """Explains an investigation via an Ollama chat model."""

    name = "ollama"

    def __init__(
        self,
        *,
        url: str,
        model: str,
        timeout: float = 60.0,
        http: HttpClient | None = None,
        prompt_builder: PromptBuilder | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._model = model
        # AI explanation is best-effort: a down model should fail fast, not retry.
        self._http = http or HttpClient(timeout=timeout, max_retries=0)
        self._prompt = prompt_builder or PromptBuilder()

    async def explain(self, summary: InvestigationSummary) -> AIExplanation:
        """Explain ``summary`` via Ollama; never raises (see module docstring)."""
        prompt = self._prompt.build(summary)
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
            "stream": False,
            "format": "json",
            "think": False,
            "options": {"temperature": 0, "seed": 0},
        }
        try:
            response = await self._http.post_json(f"{self._url}/api/chat", json_body=body)
        except ProviderTimeout as exc:
            return self._fail(AIStatus.TIMEOUT, str(exc) or "request timed out")
        except ProviderServerError as exc:
            return self._fail(AIStatus.ERROR, str(exc) or "server error")
        except ProviderNetworkError as exc:
            return self._fail(AIStatus.UNAVAILABLE, str(exc) or "connection error")
        except ProviderHttpError as exc:
            return self._fail(AIStatus.UNAVAILABLE, str(exc) or "http error")
        except Exception as exc:  # defensive: never let the AI layer raise
            return self._fail(AIStatus.ERROR, f"internal error: {type(exc).__name__}")

        if response.status_code != 200:
            return self._fail(AIStatus.ERROR, f"HTTP {response.status_code}")
        return self._parse(response.text, summary)

    # --- parsing & grounding --------------------------------------------- #

    def _parse(self, text: str, summary: InvestigationSummary) -> AIExplanation:
        content = _chat_content(text)
        if content is None:
            return self._fail(AIStatus.INVALID_RESPONSE, "malformed provider response")
        raw_json = _extract_json(content)
        if raw_json is None:
            return self._fail(AIStatus.INVALID_RESPONSE, "no JSON object in model output")
        try:
            raw = _RawExplanation.model_validate(raw_json)
        except ValidationError:
            return self._fail(AIStatus.INVALID_RESPONSE, "model output failed schema validation")
        return self._ground(raw, summary)

    def _ground(self, raw: _RawExplanation, summary: InvestigationSummary) -> AIExplanation:
        """Drop any explanation referencing a finding/recommendation not in the summary."""
        finding_ids = {finding.id for finding in summary.findings}
        rec_keys = {(rec.action.value, rec.target_value) for rec in summary.recommendations}

        findings = [
            FindingExplanation(finding_id=item.finding_id, explanation=item.explanation.strip())
            for item in raw.finding_explanations
            if item.finding_id in finding_ids and item.explanation.strip()
        ]
        recommendations = [
            RecommendationExplanation(
                action=item.action,
                target_value=item.target_value,
                explanation=item.explanation.strip(),
            )
            for item in raw.recommendation_explanations
            if (item.action, item.target_value) in rec_keys and item.explanation.strip()
        ]

        limitations = [line.strip() for line in raw.limitations if line.strip()]
        dropped = (len(raw.finding_explanations) - len(findings)) + (
            len(raw.recommendation_explanations) - len(recommendations)
        )
        if dropped > 0:
            limitations.append(
                f"{dropped} ungrounded statement(s) referencing unknown "
                "findings/recommendations were removed."
            )

        # Free-form model prose is intentionally not returned: it cannot be
        # proven grounded by checking IDs alone. Keep summaries deterministic
        # and derive them only from the validated investigation object.
        finding_count = len(summary.findings)
        executive_summary = (
            f"Investigation completed for {summary.entity_type.value} "
            f"{summary.entity_value!r}; {finding_count} finding(s) were produced "
            "by the deterministic engine."
        )
        technical_summary = " ".join(
            [
                f"Engine version: {summary.engine_version}.",
                "Findings: "
                + ("; ".join(f"{f.id}: {f.title}" for f in summary.findings) or "none."),
            ]
        )

        return AIExplanation(
            status=AIStatus.OK,
            provider=self.name,
            model=self._model,
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            finding_explanations=findings,
            recommendation_explanations=recommendations,
            limitations=limitations,
        )

    def _fail(self, status: AIStatus, reason: str) -> AIExplanation:
        """Log the raw reason server-side and return a friendly structured result.

        The reason is for operators (logs) only â€” it is never surfaced to the
        analyst; the frontend renders its own curated, non-alarming copy.
        """
        logger.warning(
            "AI explanation failed [%s] via %s/%s: %s",
            status.value,
            self.name,
            self._model,
            reason,
        )
        if status is AIStatus.TIMEOUT:
            return AIExplanation.timeout(provider=self.name, model=self._model)
        if status is AIStatus.INVALID_RESPONSE:
            return AIExplanation.invalid_response(provider=self.name, model=self._model)
        if status is AIStatus.ERROR:
            return AIExplanation.error(provider=self.name, model=self._model)
        return AIExplanation.unavailable(provider=self.name, model=self._model)


def _chat_content(text: str) -> str | None:
    """Pull ``message.content`` out of an Ollama /api/chat response body."""
    try:
        payload = json.loads(text)
        content = payload["message"]["content"]
    except (ValueError, KeyError, TypeError):
        return None
    return content if isinstance(content, str) else None


def _extract_json(text: str) -> dict[str, Any] | None:
    """Parse a JSON object from model output, tolerating think-tags/fences/prose."""
    candidates = [text, _THINK_TAG.sub("", text)]
    for candidate in candidates:
        cleaned = candidate.strip()
        try:
            parsed = json.loads(cleaned)
        except ValueError:
            start, end = cleaned.find("{"), cleaned.rfind("}")
            if start == -1 or end <= start:
                continue
            try:
                parsed = json.loads(cleaned[start : end + 1])
            except ValueError:
                continue
        if isinstance(parsed, dict):
            return parsed
    return None
