"""Rule validators for the freeze suite (Phase 4.5).

Parser-level structural validation for all nine languages, plus an *optional*
native-validation layer that is used only when the relevant toolchain is
installed. No native validator is bundled or required in CI (that would add an
external runtime dependency): ``native_available()`` reports what is present and
the freeze tests skip native checks otherwise, falling back to the parser-level
checks documented here.
"""

from __future__ import annotations

import shutil

import yaml

from threatlens.detection import DetectionLanguage

_SIEM_TOKENS = {
    DetectionLanguage.SPLUNK_SPL: ("index=",),
    DetectionLanguage.SENTINEL_KQL: ("| where",),
    DetectionLanguage.ELASTIC_ESQL: ("FROM ", "WHERE "),
    DetectionLanguage.CHRONICLE_YARA_L: ("rule ", "events:", "condition:"),
    DetectionLanguage.QRADAR_AQL: ("SELECT ", "FROM "),
}


def validate_rule(language: DetectionLanguage, content: str) -> tuple[bool, str]:
    """Parser-level validation; returns ``(ok, reason)``."""
    if language is DetectionLanguage.SIGMA:
        return _validate_sigma(content)
    if language is DetectionLanguage.YARA:
        if "rule " not in content or "condition:" not in content:
            return False, "missing rule/condition"
        if not _balanced(content, "{", "}"):
            return False, "unbalanced braces"
        return True, ""
    if language in (DetectionLanguage.SURICATA, DetectionLanguage.SNORT):
        if not content.lstrip().startswith("alert "):
            return False, "no alert header"
        for tok in ("msg:", "sid:", "rev:", "classtype:"):
            if tok not in content:
                return False, f"missing {tok}"
        if not _balanced(content, "(", ")"):
            return False, "unbalanced parens"
        return True, ""
    for tok in _SIEM_TOKENS.get(language, ()):
        if tok not in content:
            return False, f"missing '{tok.strip()}'"
    if language is DetectionLanguage.CHRONICLE_YARA_L and not _balanced(content, "{", "}"):
        return False, "unbalanced braces"
    return True, ""


def _validate_sigma(content: str) -> tuple[bool, str]:
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        return False, f"yaml: {exc}"
    if not isinstance(doc, dict):
        return False, "not a mapping"
    for key in ("title", "id", "logsource", "detection"):
        if key not in doc:
            return False, f"missing '{key}'"
    detection = doc.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        return False, "missing detection.condition"
    return True, ""


def _balanced(content: str, opener: str, closer: str) -> bool:
    """Balance ``opener``/``closer`` ignoring quoted regions (both quote styles)."""
    depth = 0
    quote: str | None = None
    escaped = False
    for char in content:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and quote is None


# --------------------------------------------------------------------------- #
# Optional native validation (used only when the toolchain is installed)
# --------------------------------------------------------------------------- #


def native_available() -> dict[str, bool]:
    """Which native validators are present in this environment (all optional)."""
    available = {"sigma": False, "yara": False, "suricata": False, "snort": False}
    try:  # pragma: no cover - depends on optional install
        import sigma  # noqa: F401

        available["sigma"] = True
    except ImportError:
        pass
    try:  # pragma: no cover - depends on optional install
        import yara  # noqa: F401

        available["yara"] = True
    except ImportError:
        pass
    available["suricata"] = shutil.which("suricata") is not None
    available["snort"] = shutil.which("snort") is not None
    return available


def native_validate_yara(content: str) -> bool:  # pragma: no cover - optional path
    """Compile a YARA rule with ``yara-python`` (only call when available)."""
    import yara

    try:
        yara.compile(source=content)
        return True
    except yara.Error:
        return False
