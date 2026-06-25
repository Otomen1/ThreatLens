"""Tests for input normalization / refanging."""

from __future__ import annotations

import pytest

from threatlens.search.normalize import refang

REFANG_CASES = [
    # defanged -> refanged
    ("hxxp://evil.com", "http://evil.com"),
    ("hXXps://evil.com", "https://evil.com"),
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil{.}com", "evil.com"),
    ("evil[dot]com", "evil.com"),
    ("evil(dot)com", "evil.com"),
    ("185[.]100[.]10[.]15", "185.100.10.15"),
    ("user[@]example[.]com", "user@example.com"),
    ("user(at)example(dot)com", "user@example.com"),
    ("hxxps[://]evil[.]com/path", "https://evil.com/path"),
    # wrapping characters stripped
    ('"8.8.8.8"', "8.8.8.8"),
    ("<http://evil.com>", "http://evil.com"),
    # whitespace trimmed
    ("  8.8.8.8  ", "8.8.8.8"),
    # already clean -> unchanged
    ("https://google.com", "https://google.com"),
    ("8.8.8.8", "8.8.8.8"),
]

# Built with chr() so the source stays pure ASCII and the code points are exact.
_ZWSP = chr(0x200B)  # zero-width space
_BOM = chr(0xFEFF)  # zero-width no-break space / BOM
_ZWJ = chr(0x200D)  # zero-width joiner
_NBSP = chr(0x00A0)  # non-breaking space

REFANG_UNICODE_CASES = [
    ("goo" + _ZWSP + "gle.com", "google.com"),
    (_BOM + "8.8.8.8", "8.8.8.8"),
    ("evil" + _ZWJ + ".com", "evil.com"),
    (_NBSP + "8.8.8.8" + _NBSP, "8.8.8.8"),
]


@pytest.mark.parametrize("raw,expected", REFANG_CASES + REFANG_UNICODE_CASES)
def test_refang(raw: str, expected: str) -> None:
    assert refang(raw) == expected


def test_refang_preserves_registry_backslashes() -> None:
    # Registry separators must survive refanging untouched.
    assert refang(r"HKCU\Software\Microsoft") == r"HKCU\Software\Microsoft"


def test_refang_whitespace_only() -> None:
    assert refang("   ") == ""
