"""Input normalization and IOC refanging.

``refang`` reverses common defanging tricks (``hxxp``, ``[.]``, ``(dot)``,
``[:]``, ``[@]``) and strips zero-width / wrapping characters so detectors see
a clean candidate. It is intentionally conservative: only clearly-bracketed
defang markers are reversed, never ambiguous bare words, so it cannot corrupt
legitimate input such as registry paths or free text.

The original input is preserved as ``Entity.value``; the refanged/normalized
form drives detection and becomes ``Entity.normalized_value``.
"""

from __future__ import annotations

import re

# Character cleanup applied up front:
#   - zero-width / BOM-like characters are removed
#   - non-breaking space is folded to a regular space
_TRANSLATE = {
    0x200B: None,  # zero-width space
    0x200C: None,  # zero-width non-joiner
    0x200D: None,  # zero-width joiner
    0x2060: None,  # word joiner
    0xFEFF: None,  # BOM / zero-width no-break space
    0x00A0: ord(" "),  # non-breaking space -> space
}

# Characters frequently wrapping a pasted indicator.
_WRAPPERS = "<>\"'“”‘’"

_HXXP_RE = re.compile(r"hxxp", re.IGNORECASE)
_BRACKET_DOT_RE = re.compile(r"[\[\(\{]\s*\.\s*[\]\)\}]")
_BRACKET_DOT_WORD_RE = re.compile(r"[\[\(\{]\s*dot\s*[\]\)\}]", re.IGNORECASE)
_BRACKET_COLON_SLASH_RE = re.compile(r"[\[\(\{]\s*://\s*[\]\)\}]")
_BRACKET_COLON_RE = re.compile(r"[\[\(\{]\s*:\s*[\]\)\}]")
_BRACKET_AT_RE = re.compile(r"[\[\(\{]\s*@\s*[\]\)\}]")
_BRACKET_AT_WORD_RE = re.compile(r"[\[\(\{]\s*at\s*[\]\)\}]", re.IGNORECASE)


def refang(text: str) -> str:
    """Return a cleaned, refanged form of ``text`` for detection.

    Whitespace-stripped, zero-width-cleaned, unwrapped, and with common defang
    markers reversed. Safe to call on already-clean input (no-op).
    """
    t = text.translate(_TRANSLATE).strip()
    # Remove a single layer of wrapping punctuation from each end.
    t = t.strip(_WRAPPERS).strip()

    t = _HXXP_RE.sub("http", t)  # hxxp -> http, hxxps -> https
    t = _BRACKET_COLON_SLASH_RE.sub("://", t)
    t = _BRACKET_DOT_RE.sub(".", t)
    t = _BRACKET_DOT_WORD_RE.sub(".", t)
    t = _BRACKET_COLON_RE.sub(":", t)
    t = _BRACKET_AT_RE.sub("@", t)
    t = _BRACKET_AT_WORD_RE.sub("@", t)
    return t.strip()
