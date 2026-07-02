# Phase 4.2 — YARA Detection Generator

## Status

The second concrete detection generator. `YaraGenerator`
(`backend/src/threatlens/detection/future/yara.py`) converts
`InvestigationSummary` findings into deterministic **YARA** rules and is
registered in `build_default_registry()` next to Sigma. No engine change, no API
change: `POST /api/v1/detections` now returns Sigma **and** YARA artifacts when
applicable. No AI, no validation, no other languages.

## Architecture

A pure `DetectionGenerator` that reads **only** `Finding` objects — never
providers, raw TI, WHOIS, or NVD/MITRE JSON. No network, no wall clock. It reuses
the framework verbatim (`DetectionRegistry`, `DetectionPackage`,
`DetectionArtifact`, `TemplateRegistry`, `compute_artifact_id`); the engine orders
and de-duplicates across all registered generators.

## Supported finding mappings

YARA detects **files**, so rules are emitted **only** for findings whose subject
is a valid file hash:

| Finding subject | YARA condition |
|---|---|
| `md5` (32 hex) | `hash.md5(0, filesize) == "…"` |
| `sha1` (40 hex) | `hash.sha1(0, filesize) == "…"` |
| `sha256` (64 hex) | `hash.sha256(0, filesize) == "…"` |

Every rule uses the `hash` module (`import "hash"`) with a `filesize < 100MB`
guard, plus a full `meta:` block (description, author, date, reference,
`finding_ids`, `rule_id`, `detection_id`, source, `threatlens_version`, severity,
hash, and `mitre_attack` when the finding cites a technique). Severity is copied
from the finding into the `severity` meta (never recomputed). Findings on the same
hash are merged into one rule citing all finding ids (duplicate suppression).

**Never emitted for:** IPs, domains, URLs, CVE, CWE, CAPEC, threat actors, ATT&CK
techniques, malware-family *names*, informational findings, or malformed hashes.
Bare names carry no file content to match, so — per the rule philosophy — no rule
is emitted (a weak/IOC-style rule is worse than none). YARA rules therefore never
contain an IP, domain, or URL IOC.

## IDs

Deterministic and timestamp-independent, no randomness, no UUID4: the YARA
`rule` name (`ThreatLens_Malware_<12 hex>`) and `rule_id` (`yar_<16 hex>`) hash
only the file hash, so the same file always yields the same rule across
executions. The framework artifact id (`det_…`) hashes the rule structure
**excluding** the `date`. The `date` meta reflects the investigation
(`summary.generated_at`, never the clock) but is excluded from identity.

## Relationship with Sigma

Independent, coexisting generators. A file-hash finding yields **both** a Sigma
rule (host telemetry: `process_creation` `Hashes|contains`) and a YARA rule (file
scanning: `hash` module) — complementary detections for the same indicator.
Sigma is untouched by this phase.

## Relationship with InvestigationSummary

Strictly downstream and read-only. YARA generation never influences findings,
confidence, severity, priority, recommendations, or relationships. The Reasoning
Engine remains the only source of truth.

## Limitations

- Hash-only. String/PE-structure rules require the sample's bytes, which
  ThreatLens never has — a later capability, not speculated here.
- No `strings:` section (a hash rule needs none; an empty block is invalid YARA).
- No YARA compilation/validation (`UNVALIDATED`; a later phase).

## Frontend

The Detection Engineering panel already renders any artifact (language, title,
severity, category, finding IDs, source, copy, download); YARA needed only a
`.yar` download extension. Read-only.

## Example

```
import "hash"

rule ThreatLens_Malware_0364e78be895
{
    meta:
        description = "Detects a file matching a hash flagged as malicious by ThreatLens finding(s) fnd_… via malwarebazaar."
        author = "ThreatLens Detection Engine"
        date = "2024-06-01"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        finding_ids = "fnd_…"
        rule_id = "yar_0364e78be895cef9"
        detection_id = "det_a4181fdfe089b0cb"
        source = "Generated from InvestigationSummary"
        threatlens_version = "1.0.0"
        severity = "critical"
        hash_type = "sha256"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        mitre_attack = "T1204.002"
    condition:
        filesize < 100MB and hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

## Testing & performance

`backend/tests/test_yara_generator.py` (16 tests): registration alongside Sigma,
per-hash mapping, rejection of all non-file/invalid subjects, no-network-IOC
guarantee, structure+traceability meta, determinism, timestamp-independent stable
ids, duplicate suppression, serialization, a **golden snapshot**, and the API
contract. Frontend helper tests cover the `.yar` filename. The Reasoning Engine
and its golden suites are untouched.

Generation is linear and cheap: **1 finding ≈ 0.04 ms, 10 ≈ 0.36 ms, 50 ≈ 1.8 ms,
100 ≈ 3.7 ms** (~37 µs/rule).
