"""The core classification table.

A large, deterministic ``input -> (expected type, expected normalized value)``
table covering every entity type, defanged forms, normalization, ambiguous and
adversarial inputs. This is the highest-value test surface for the engine.
"""

from __future__ import annotations

import pytest

from threatlens.entities.types import EntityType as ET
from threatlens.search import detect

# (raw_input, expected_type, expected_normalized_value | None to skip the check)
CASES: list[tuple[str, ET, str | None]] = [
    # --- IPv4 ---
    ("185.100.10.15", ET.IPV4, "185.100.10.15"),
    ("8.8.8.8", ET.IPV4, "8.8.8.8"),
    ("1.1.1.1", ET.IPV4, "1.1.1.1"),
    ("255.255.255.255", ET.IPV4, "255.255.255.255"),
    ("185[.]100[.]10[.]15", ET.IPV4, "185.100.10.15"),  # defanged
    # --- IPv6 ---
    ("2001:db8::1", ET.IPV6, "2001:db8::1"),
    ("::1", ET.IPV6, "::1"),
    ("fe80::1", ET.IPV6, "fe80::1"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", ET.IPV6, "2001:db8::1"),  # compressed
    # --- Domain ---
    ("google.com", ET.DOMAIN, "google.com"),
    ("www.google.co.uk", ET.DOMAIN, "www.google.co.uk"),
    ("EXAMPLE.COM", ET.DOMAIN, "example.com"),
    ("sub.example.com.", ET.DOMAIN, "sub.example.com"),  # trailing dot
    ("evil[.]com", ET.DOMAIN, "evil.com"),  # defanged
    ("xn--80ak6aa92e.com", ET.DOMAIN, "xn--80ak6aa92e.com"),  # punycode
    # --- URL ---
    ("https://google.com", ET.URL, "https://google.com"),
    ("http://example.com/path?q=1", ET.URL, "http://example.com/path?q=1"),
    ("https://example.com:443/x", ET.URL, "https://example.com/x"),  # default port dropped
    ("http://example.com:8080/", ET.URL, "http://example.com:8080/"),
    ("ftp://files.example.com/f", ET.URL, "ftp://files.example.com/f"),
    ("hxxp://evil[.]com/abc", ET.URL, "http://evil.com/abc"),  # defanged
    # --- Email ---
    ("user@example.com", ET.EMAIL, "user@example.com"),
    ("First.Last@Example.COM", ET.EMAIL, "First.Last@example.com"),  # domain lowered
    ("user[@]example[.]com", ET.EMAIL, "user@example.com"),  # defanged
    # --- Hashes ---
    ("d41d8cd98f00b204e9800998ecf8427e", ET.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
    ("D41D8CD98F00B204E9800998ECF8427E", ET.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", ET.SHA1, None),
    (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ET.SHA256,
        None,
    ),
    # --- CVE ---
    ("CVE-2026-12345", ET.CVE, "CVE-2026-12345"),
    ("cve-2021-44228", ET.CVE, "CVE-2021-44228"),
    # --- MITRE technique ---
    ("T1059", ET.MITRE_TECHNIQUE, "T1059"),
    ("T1059.001", ET.MITRE_TECHNIQUE, "T1059.001"),
    ("t1003.001", ET.MITRE_TECHNIQUE, "T1003.001"),
    # --- Registry key ---
    ("HKCU\\Software\\Microsoft", ET.REGISTRY_KEY, "HKEY_CURRENT_USER\\Software\\Microsoft"),
    (
        "HKLM\\System\\CurrentControlSet",
        ET.REGISTRY_KEY,
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet",
    ),
    ("HKEY_LOCAL_MACHINE\\SOFTWARE", ET.REGISTRY_KEY, "HKEY_LOCAL_MACHINE\\SOFTWARE"),
    # --- Process name ---
    ("powershell.exe", ET.PROCESS_NAME, "powershell.exe"),
    ("RUNDLL32.EXE", ET.PROCESS_NAME, "rundll32.exe"),
    ("randomtool.exe", ET.PROCESS_NAME, "randomtool.exe"),
    ("evil.dll", ET.PROCESS_NAME, "evil.dll"),
    # --- PowerShell command ---
    ("Invoke-WebRequest", ET.POWERSHELL_COMMAND, "Invoke-WebRequest"),
    ("invoke-expression", ET.POWERSHELL_COMMAND, "Invoke-Expression"),
    ("Get-Process", ET.POWERSHELL_COMMAND, "Get-Process"),
    ("New-Object", ET.POWERSHELL_COMMAND, "New-Object"),
    # --- Windows API ---
    ("VirtualAlloc", ET.WINDOWS_API, "VirtualAlloc"),
    ("virtualalloc", ET.WINDOWS_API, "VirtualAlloc"),
    ("CreateRemoteThread", ET.WINDOWS_API, "CreateRemoteThread"),
    ("NtCreateThreadEx", ET.WINDOWS_API, "NtCreateThreadEx"),
    ("ZwQueryObscureThing", ET.WINDOWS_API, "ZwQueryObscureThing"),  # native heuristic
    # --- Threat actor ---
    ("APT29", ET.THREAT_ACTOR, "APT29"),
    ("apt28", ET.THREAT_ACTOR, "APT28"),
    ("Cozy Bear", ET.THREAT_ACTOR, "APT29"),
    ("Fancy Bear", ET.THREAT_ACTOR, "APT28"),
    ("Lazarus", ET.THREAT_ACTOR, "Lazarus Group"),
    ("APT35", ET.THREAT_ACTOR, "Charming Kitten"),
    # --- Malware family ---
    ("Emotet", ET.MALWARE_FAMILY, "Emotet"),
    ("ClickFix", ET.MALWARE_FAMILY, "ClickFix"),
    ("qbot", ET.MALWARE_FAMILY, "Qakbot"),
    ("trickbot", ET.MALWARE_FAMILY, "TrickBot"),
    # --- Fallbacks / invalid ---
    ("asdfghjklqwerty", ET.UNKNOWN, None),
    ("the quick brown fox", ET.FREETEXT, None),
    ("1.2.3.4.5", ET.UNKNOWN, None),  # not a valid IPv4
    ("999.999.999.999", ET.UNKNOWN, None),  # octets out of range
    ("CVE-21-1", ET.UNKNOWN, None),  # malformed CVE
    ("T1059.0011", ET.UNKNOWN, None),  # malformed sub-technique
]


@pytest.mark.parametrize("raw,expected_type,expected_norm", CASES)
def test_detection_table(raw: str, expected_type: ET, expected_norm: str | None) -> None:
    entity = detect(raw)
    assert entity.type == expected_type, f"{raw!r} -> {entity.type} (want {expected_type})"
    if expected_norm is not None:
        assert entity.normalized_value == expected_norm
    # The original input is always preserved verbatim (after trimming).
    assert entity.value == raw.strip()
