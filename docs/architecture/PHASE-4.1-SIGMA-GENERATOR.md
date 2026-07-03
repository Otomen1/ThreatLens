# Phase 4.1 — Sigma Detection Generator

## Status

The **first concrete generator** for the Detection Engineering Framework
(Phase 4.0). It converts deterministic `InvestigationSummary` findings into
minimal, readable **Sigma** rules. No AI, no provider access, no wall clock, no
Sigma validation (that is a later phase). Only Sigma — YARA/Suricata/Snort/
KQL/SPL/Elastic/Sentinel remain later phases.

## Generator architecture

`SigmaGenerator` lives at `backend/src/threatlens/detection/future/sigma.py` and
implements the framework's `DetectionGenerator` interface. It is registered in
`detection.registry.build_default_registry()` (a lazy import that avoids an
engine↔generator cycle), so the **engine and API are unchanged** — the registry
discovers and runs it automatically. `POST /api/v1/detections` now returns Sigma
artifacts with no endpoint change.

It is a **pure consumer**: `generate(summary)` reads **only** `Finding` objects.
It never inspects provider responses, raw TI, reputation scores, WHOIS, NVD JSON,
or MITRE JSON — those never even reach the generator (the engine passes it only
the `InvestigationSummary`). It never performs I/O, calls AI, reads the clock, or
mutates the summary, so identical findings always produce identical Sigma.

```
InvestigationSummary → Finding[] → (eligible IOC findings, grouped by IOC) → Sigma DetectionArtifact[]
```

## Sigma mapping philosophy

Rules are **minimal and readable** — one `selection` matching the indicator in a
standard log source, `condition: selection`, no vendor-specific optimization and
**no speculative conditions**. Findings on the same IOC are merged into one rule
that cites every contributing finding (duplicate suppression + full provenance).

| Finding subject | Log source | Field | Category |
|---|---|---|---|
| `ipv4` / `ipv6` | `firewall` | `dst_ip` | network |
| `domain` | `dns` | `query` | dns |
| `url` | `proxy` | `c-uri\|contains` | http |
| `md5` / `sha1` / `sha256` | `process_creation` (windows) | `Hashes\|contains` | file |

Severity is **copied** from the finding (never recomputed) into the Sigma `level`
(informational/low/medium/high/critical). ATT&CK techniques cited by a finding's
relationships become `attack.tXXXX` tags and `https://attack.mitre.org/…`
references.

### Every rule carries provenance

No rule exists without traceability. Each artifact:

- puts `finding_ids` (and `subject`, `subject_type`, `sigma_id`, `sources`,
  `attack`) in `DetectionArtifact.metadata`;
- cites each **Finding ID**, the **subject**, **MITRE ATT&CK** (when the finding
  carries an ATT&CK relationship), and the **evidence sources** in the rule's
  `references` and `description`.

### Identity

- The Sigma `id` (a **UUIDv5**) is keyed on `subject_type | subject_value |
  field` — the same IOC always yields the same rule id, across investigations and
  days.
- The framework artifact id (`det_…`) and the package id hash only **stable**
  values — subject, log source, provenance, and the rule structure **excluding
  the `date`** — so re-generating the same detection yields the same ids (no
  timestamps, no randomness).
- The human-readable `date` field carries the investigation date
  (`summary.generated_at`, never the wall clock) but is deliberately excluded
  from identity. This mirrors real Sigma lifecycle: stable UUID, updatable date.

## Supported vs unsupported findings

**Generates Sigma for** actionable (severity above informational),
log-observable IOC findings: malicious IPv4/IPv6, domains, URLs, and file hashes.

**Never generates Sigma for** CWE, CAPEC, CVE, informational findings, or
unsupported subject types. ATT&CK techniques, malware families, and threat actors
as *subjects* do not produce a standalone rule — there is no non-speculative log
field to match on a bare technique/actor/malware name — but their ATT&CK context
enriches the tags and references of the IOC rules generated from the same
investigation.

## Templates

Per-IOC-kind `DetectionTemplate` objects live in a module-level `TemplateRegistry`
(the framework's, from Phase 4.0) and fix each rule's language, target, category,
and capabilities. The YAML is rendered by a pure, hand-rolled function (no YAML
dependency in production, fully deterministic key order) — never hardcoded in the
engine.

## Limitations

- No Sigma **validation** yet (syntax/schema); every artifact is `UNVALIDATED`
  (Phase 4.6).
- No behavioral rules for techniques/actors/malware families (needs behavioral
  templates, a later phase).
- One `selection` per IOC; no correlation, aggregation, or timeframes.
- Log-source/field choices are standard and portable, not tuned per SIEM.

## Extension strategy

Adding the next generator (YARA, Suricata, …) is the same shape and requires **no
engine or API change**:

1. Add `detection/future/<language>.py` implementing `DetectionGenerator`
   (pure; consumes only `Finding`s).
2. Register per-kind `DetectionTemplate`s and render content deterministically.
3. Register the generator in `build_default_registry()`.

The engine orders and de-duplicates artifacts across all registered generators;
the package, API, and frontend already understand multi-language packages.

## Example

A malicious-IP finding (`45.155.205.233`, critical, ATT&CK `T1071.001`) yields:

```yaml
title: 'Malicious IP address: 45.155.205.233'
id: 646fb072-055e-57f5-884e-dc3d85885caf
status: experimental
description: 'Detects network connections to 45.155.205.233, flagged as malicious by ThreatLens finding(s) fnd_… via abuseipdb.'
author: 'ThreatLens Detection Engine'
references:
    - 'https://attack.mitre.org/techniques/T1071/001/'
    - 'ThreatLens finding: fnd_…'
date: 2024-06-01
tags:
    - threatlens.detection
    - attack.t1071.001
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '45.155.205.233'
    condition: selection
falsepositives:
    - 'Legitimate traffic to this destination'
level: critical
```

## Testing & performance

`backend/tests/test_sigma_generator.py` (18 tests): registry execution, per-IOC
mapping, unsupported/informational filtering, valid+complete YAML (parsed as real
YAML), severity→level, traceability (finding ids/subject/ATT&CK), determinism,
timestamp-independent stable ids, duplicate suppression, serialization, a **golden
snapshot** of the exact YAML, and the API contract. Two Phase 4.0 tests were
updated for the now-populated default registry. Frontend helper tests cover the
rendering helpers. The Reasoning Engine and its golden suites are untouched.

Generation is linear and cheap (single-threaded, no I/O): **1 finding ≈ 0.07 ms,
10 ≈ 0.55 ms, 50 ≈ 2.5 ms, 100 ≈ 5.1 ms** (~50 µs/finding).
