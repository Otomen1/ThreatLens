"""Offline deterministic validation for generated detection artifacts."""

from __future__ import annotations

import re

from .models import DetectionArtifact, DetectionValidation
from .types import DetectionLanguage, DetectionValidationStatus


def test_sigma_rule(content: str, sample_logs: tuple[dict[str, object], ...]) -> tuple[bool, int, tuple[str, ...]]:
    """Validate a Sigma rule and evaluate simple selectors against JSON logs."""
    try:
        import yaml
        document = yaml.safe_load(content)
    except Exception as exc:
        return False, 0, (f"Sigma YAML could not be parsed: {exc}",)
    if not isinstance(document, dict) or not isinstance(document.get("detection"), dict):
        return False, 0, ("Sigma detection must be a mapping",)
    detection = document["detection"]
    condition = detection.get("condition", "")
    selectors = {name: value for name, value in detection.items() if name != "condition"}
    if not isinstance(condition, str) or not selectors:
        return False, 0, ("Sigma detection needs selectors and a condition",)
    matched = 0
    for log in sample_logs:
        hits = [name for name, selector in selectors.items() if _selector_matches(selector, log)]
        if condition.strip() in hits or condition.strip() == " or ".join(hits) or ("all of" in condition and len(hits) == len(selectors)):
            matched += 1
    return True, matched, ()


def _selector_matches(selector: object, log: dict[str, object]) -> bool:
    if not isinstance(selector, dict):
        return False
    return all(any(str(log.get(field, "")).lower() == str(value).lower() for field in (field_name, field_name.lower())) for field_name, value in selector.items())


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
        required = {
            DetectionLanguage.SPLUNK_SPL: ("index=",),
            DetectionLanguage.SENTINEL_KQL: ("| where",),
            DetectionLanguage.ELASTIC_ESQL: ("FROM ", "WHERE "),
            DetectionLanguage.CHRONICLE_YARA_L: ("rule ", "events:", "condition:"),
            DetectionLanguage.QRADAR_AQL: ("SELECT ", "FROM "),
        }.get(artifact.language, ())
        for token in required:
            if token not in artifact.content:
                messages.append(f"missing required token '{token.strip()}'")
        if artifact.content.count("{") != artifact.content.count("}"):
            messages.append("braces are unbalanced")
        if not required and not messages:
            messages.append("syntax validation requires the target platform parser")
    return DetectionValidation(
        status=DetectionValidationStatus.VALID if not messages else DetectionValidationStatus.INVALID,
        validator="threatlens.offline",
        messages=tuple(messages),
    )


def validate_package(artifacts: tuple[DetectionArtifact, ...]) -> tuple[DetectionArtifact, ...]:
    return tuple(a.model_copy(update={"validation": validate_artifact(a)}) for a in artifacts)
