"""Unit tests for the freeze-suite rule validators (Phase 4.5).

The parser-level validators in ``validate.py`` are load-bearing: the freeze's
"every generated rule is structurally valid" claim rests on them, so they are
tested directly here (happy path + the specific rejection reasons) rather than
only implicitly through the corpus.
"""

from __future__ import annotations

import pytest

from threatlens.detection import DetectionLanguage

from .validate import _balanced, _validate_sigma, native_available, validate_rule

_L = DetectionLanguage

# --------------------------------------------------------------------------- #
# Minimal, structurally-valid exemplars for every language
# --------------------------------------------------------------------------- #

_VALID_SIGMA = (
    "title: t\n"
    "id: 00000000-0000-0000-0000-000000000000\n"
    "logsource:\n"
    "  category: process_creation\n"
    "detection:\n"
    "  sel:\n"
    "    Image: x\n"
    "  condition: sel\n"
)
_VALID_YARA = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}'
_VALID_SURICATA = (
    'alert tcp any any -> any any (msg:"x"; content:"y"; '
    "sid:1000001; rev:1; classtype:trojan-activity;)"
)
_VALID_SNORT = _VALID_SURICATA
_VALID_SPLUNK = 'index=main sourcetype=firewall dest_ip="1.2.3.4"'
_VALID_SENTINEL = 'CommonSecurityLog\n| where DestinationIP == "1.2.3.4"'
_VALID_ELASTIC = 'FROM logs-*\n| WHERE destination.ip == "1.2.3.4"'
_VALID_CHRONICLE = 'rule r {\n  events:\n    $e.principal.ip = "1.2.3.4"\n  condition:\n    $e\n}'
_VALID_QRADAR = "SELECT sourceip FROM events WHERE destinationip = '1.2.3.4'"

_VALID: list[tuple[DetectionLanguage, str]] = [
    (_L.SIGMA, _VALID_SIGMA),
    (_L.YARA, _VALID_YARA),
    (_L.SURICATA, _VALID_SURICATA),
    (_L.SNORT, _VALID_SNORT),
    (_L.SPLUNK_SPL, _VALID_SPLUNK),
    (_L.SENTINEL_KQL, _VALID_SENTINEL),
    (_L.ELASTIC_ESQL, _VALID_ELASTIC),
    (_L.CHRONICLE_YARA_L, _VALID_CHRONICLE),
    (_L.QRADAR_AQL, _VALID_QRADAR),
]


@pytest.mark.parametrize("language,content", _VALID, ids=lambda v: getattr(v, "value", ""))
def test_valid_rules_pass(language: DetectionLanguage, content: str) -> None:
    ok, reason = validate_rule(language, content)
    assert ok, f"{language.value} should validate, got: {reason}"
    assert reason == ""


# --------------------------------------------------------------------------- #
# Rejections carry a specific, actionable reason
# --------------------------------------------------------------------------- #

_MALFORMED: list[tuple[str, DetectionLanguage, str, str]] = [
    ("sigma_scalar", _L.SIGMA, "just a bare scalar", "not a mapping"),
    ("sigma_no_title", _L.SIGMA, "id: x\nlogsource: {}\ndetection:\n  condition: a\n", "title"),
    (
        "sigma_no_condition",
        _L.SIGMA,
        "title: t\nid: x\nlogsource: {}\ndetection:\n  sel: 1\n",
        "detection.condition",
    ),
    ("yara_no_condition", _L.YARA, "rule r {\n  strings:\n    $a = 1\n}", "missing rule/condition"),
    ("yara_no_rule", _L.YARA, "condition: $a", "missing rule/condition"),
    ("yara_unbalanced", _L.YARA, "rule r {\n  condition:\n    $a\n", "unbalanced braces"),
    (
        "suricata_no_alert",
        _L.SURICATA,
        'drop tcp any any -> any any (msg:"x"; sid:1; rev:1; classtype:x;)',
        "no alert header",
    ),
    (
        "suricata_no_sid",
        _L.SURICATA,
        'alert tcp any any -> any any (msg:"x"; rev:1; classtype:x;)',
        "missing sid:",
    ),
    (
        "snort_unbalanced",
        _L.SNORT,
        'alert tcp any any -> any any (msg:"x"; sid:1; rev:1; classtype:x;',
        "unbalanced parens",
    ),
    ("splunk_no_index", _L.SPLUNK_SPL, 'search dest_ip="1.2.3.4"', "index="),
    ("sentinel_no_where", _L.SENTINEL_KQL, "CommonSecurityLog", "| where"),
    ("elastic_no_where", _L.ELASTIC_ESQL, "FROM logs-*", "WHERE"),
    ("chronicle_no_events", _L.CHRONICLE_YARA_L, "rule r {\n  condition: $e\n}", "events:"),
    ("qradar_no_from", _L.QRADAR_AQL, "SELECT sourceip", "FROM"),
]


@pytest.mark.parametrize("cid,language,content,needle", _MALFORMED, ids=lambda v: v)
def test_malformed_rules_are_rejected(
    cid: str, language: DetectionLanguage, content: str, needle: str
) -> None:
    del cid
    ok, reason = validate_rule(language, content)
    assert not ok
    assert needle in reason, f"expected reason to mention {needle!r}, got {reason!r}"


def test_sigma_invalid_yaml_is_rejected() -> None:
    ok, reason = _validate_sigma("a:\n\t- tab-indent is illegal")
    assert not ok
    assert "yaml" in reason


# --------------------------------------------------------------------------- #
# Delimiter balancing (quote- and escape-aware)
# --------------------------------------------------------------------------- #

_BALANCE: list[tuple[str, str, str, bool]] = [
    ("empty", "", "(", True),
    ("simple_pair", "()", "(", True),
    ("nested", "((()))", "(", True),
    ("open_only", "(()", "(", False),
    ("close_first", ")(", "(", False),
    ("opener_in_quotes", '("(")', "(", True),
    ("closer_in_quotes", '(")")', "(", True),
    ("unterminated_quote", '("', "(", False),
    ("escaped_quote_in_string", r'("\"")', "(", True),
    ("braces_ok", "{ { } }", "{", True),
    ("braces_bad", "{ }}", "{", False),
]


@pytest.mark.parametrize("cid,content,opener,expected", _BALANCE, ids=lambda v: v)
def test_balanced(cid: str, content: str, opener: str, expected: bool) -> None:
    del cid
    closer = {"(": ")", "{": "}", "[": "]"}[opener]
    assert _balanced(content, opener, closer) is expected


# --------------------------------------------------------------------------- #
# Native validation is optional and never required by CI
# --------------------------------------------------------------------------- #


def test_native_available_reports_all_four_toolchains() -> None:
    available = native_available()
    assert set(available) == {"sigma", "yara", "suricata", "snort"}
    assert all(isinstance(v, bool) for v in available.values())
