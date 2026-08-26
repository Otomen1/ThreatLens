"""Offline deterministic validation for generated detection artifacts."""

from __future__ import annotations

import re

from .models import DetectionArtifact, DetectionValidation
from .types import DetectionLanguage, DetectionValidationStatus


def validate_artifact(artifact: DetectionArtifact) -> DetectionValidation:
    """Check artifact shape and supported syntax basics without network access."""
    messages: list[str] = []
    if not artifact.content.strip():
        messages.append("rule content is empty")
    elif artifact.language is DetectionLanguage.SIGMA:
        try:
            import yaml
            document = yaml.safe_load(artifact.content)
            if not isinstance(document, dict):
                messages.append("Sigma document must be a mapping")
            else:
                for field in ("title", "logsource", "detection"):
                    if field not in document:
                        messages.append(f"Sigma document is missing '{field}'")
        except Exception as exc:
            messages.append(f"Sigma YAML could not be parsed: {exc}")
    elif artifact.language is DetectionLanguage.YARA:
        if not re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", artifact.content):
            messages.append("YARA rule declaration was not found")
        if artifact.content.count("{") != artifact.content.count("}"):
            messages.append("YARA braces are unbalanced")
    elif artifact.content.strip():
        messages.append("syntax validation requires the target platform parser")
    return DetectionValidation(
        status=DetectionValidationStatus.VALID if not messages else DetectionValidationStatus.INVALID,
        validator="threatlens.offline",
        messages=tuple(messages),
    )


def validate_package(artifacts: tuple[DetectionArtifact, ...]) -> tuple[DetectionArtifact, ...]:
    return tuple(a.model_copy(update={"validation": validate_artifact(a)}) for a in artifacts)
