"""Tests for indicator-value normalization (Phase 9.1).

Covers every type's canonical form, the deliberate "never raise, fall back
to case-fold" behavior for malformed input, and the exact identity used for
deduplication: ``(type, normalize_indicator_value(type, value))``.
"""

from __future__ import annotations

from threatlens.collections import IndicatorType
from threatlens.collections.normalize import normalize_indicator_value


class TestIpNormalization:
    def test_ipv4_unchanged_when_already_canonical(self) -> None:
        assert normalize_indicator_value(IndicatorType.IPV4, "1.1.1.1") == "1.1.1.1"

    def test_ipv4_strips_surrounding_whitespace(self) -> None:
        assert normalize_indicator_value(IndicatorType.IPV4, "  1.1.1.1  ") == "1.1.1.1"

    def test_ipv4_malformed_falls_back_to_lowercase_no_raise(self) -> None:
        """Leading-zero octets are rejected by Python's ipaddress module
        (CVE-2021-29921 hardening) — collections never reject explicitly
        provided intelligence, so this falls back to a case-fold rather than
        raising."""
        assert normalize_indicator_value(IndicatorType.IPV4, "001.001.001.001") == "001.001.001.001"

    def test_ipv6_compressed_and_expanded_forms_are_identical(self) -> None:
        expanded = normalize_indicator_value(
            IndicatorType.IPV6, "2001:0db8:0000:0000:0000:0000:0000:0001"
        )
        compressed = normalize_indicator_value(IndicatorType.IPV6, "2001:db8::1")
        assert expanded == compressed == "2001:db8::1"

    def test_ipv6_uppercase_hex_normalizes_same_as_lowercase(self) -> None:
        upper = normalize_indicator_value(IndicatorType.IPV6, "2001:DB8::1")
        lower = normalize_indicator_value(IndicatorType.IPV6, "2001:db8::1")
        assert upper == lower

    def test_ipv6_malformed_falls_back_to_lowercase_no_raise(self) -> None:
        assert normalize_indicator_value(IndicatorType.IPV6, "not-an-ip") == "not-an-ip"


class TestDomainHostnameEmailNormalization:
    def test_domain_lowercased(self) -> None:
        assert (
            normalize_indicator_value(IndicatorType.DOMAIN, "Evil.EXAMPLE.com")
            == "evil.example.com"
        )

    def test_hostname_lowercased(self) -> None:
        assert (
            normalize_indicator_value(IndicatorType.HOSTNAME, "WORKSTATION-01") == "workstation-01"
        )

    def test_email_lowercased(self) -> None:
        assert (
            normalize_indicator_value(IndicatorType.EMAIL, "Attacker@Evil.COM")
            == "attacker@evil.com"
        )

    def test_strips_whitespace(self) -> None:
        assert normalize_indicator_value(IndicatorType.DOMAIN, "  evil.com  ") == "evil.com"


class TestHashNormalization:
    def test_md5_lowercased(self) -> None:
        value = "D41D8CD98F00B204E9800998ECF8427E"
        assert normalize_indicator_value(IndicatorType.MD5, value) == value.lower()

    def test_sha1_lowercased(self) -> None:
        value = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        assert normalize_indicator_value(IndicatorType.SHA1, value) == value.lower()

    def test_sha256_lowercased(self) -> None:
        value = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        assert normalize_indicator_value(IndicatorType.SHA256, value) == value.lower()


class TestUppercaseCanonicalTypes:
    def test_cve_uppercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.CVE, "cve-2024-3094") == "CVE-2024-3094"

    def test_mitre_technique_uppercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.MITRE_TECHNIQUE, "t1059.001") == "T1059.001"

    def test_mitre_software_uppercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.MITRE_SOFTWARE, "s0154") == "S0154"

    def test_mitre_group_uppercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.MITRE_GROUP, "g0016") == "G0016"


class TestUrlNormalization:
    def test_scheme_and_host_lowercased_path_preserved(self) -> None:
        result = normalize_indicator_value(IndicatorType.URL, "HTTP://Evil.EXAMPLE.com/Payload.EXE")
        assert result == "http://evil.example.com/Payload.EXE"

    def test_equivalent_case_variants_normalize_identically(self) -> None:
        a = normalize_indicator_value(IndicatorType.URL, "HTTPS://EVIL.COM/x")
        b = normalize_indicator_value(IndicatorType.URL, "https://evil.com/x")
        assert a == b

    def test_path_case_is_significant(self) -> None:
        """Paths are case-sensitive per RFC 3986, unlike scheme/host —
        /Payload.EXE and /payload.exe are genuinely different resources."""
        a = normalize_indicator_value(IndicatorType.URL, "http://evil.com/Payload.EXE")
        b = normalize_indicator_value(IndicatorType.URL, "http://evil.com/payload.exe")
        assert a != b


class TestOtherFreeformTypes:
    def test_registry_lowercased(self) -> None:
        value = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        assert normalize_indicator_value(IndicatorType.REGISTRY, value) == value.lower()

    def test_mutex_lowercased(self) -> None:
        assert (
            normalize_indicator_value(IndicatorType.MUTEX, "Global\\MyMutex") == "global\\mymutex"
        )

    def test_filename_lowercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.FILENAME, "Evil.EXE") == "evil.exe"

    def test_process_lowercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.PROCESS, "RUNDLL32.EXE") == "rundll32.exe"

    def test_certificate_lowercased(self) -> None:
        assert normalize_indicator_value(IndicatorType.CERTIFICATE, "AA:BB:CC") == "aa:bb:cc"


class TestNormalizationIsDeterministic:
    def test_same_input_always_normalizes_identically(self) -> None:
        for _ in range(5):
            assert normalize_indicator_value(IndicatorType.DOMAIN, "Evil.COM") == "evil.com"

    def test_never_raises_for_any_string(self) -> None:
        """No normalizer ever raises — malformed input always falls back to
        a case-fold rather than rejecting the caller's explicitly provided
        intelligence."""
        wild_inputs = ["", "   ", "not valid at all !!!", "\x00\x01", "a" * 5000]
        for indicator_type in IndicatorType:
            for value in wild_inputs:
                if value.strip():
                    normalize_indicator_value(indicator_type, value)  # must not raise
