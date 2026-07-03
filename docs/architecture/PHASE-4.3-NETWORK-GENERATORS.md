# Phase 4.3 — Network Detection Generators (Suricata & Snort)

## Status

Two concrete network generators. `SuricataGenerator` and `SnortGenerator`
(`backend/src/threatlens/detection/future/{suricata,snort}.py`) convert
network-observable findings into deterministic IDS/IPS rules, registered in
`build_default_registry()` next to Sigma and YARA. No engine change, no API
change: `POST /api/v1/detections` may now return Sigma + YARA + Suricata + Snort
artifacts. No AI, no validation, no other generators.

## Architecture

Both are pure `DetectionGenerator`s that read **only** `Finding` objects — no
providers, raw TI, WHOIS, NVD/MITRE JSON, network, or wall clock. They share a
new pure helper module, `future/_netrules.py` (eligibility, deterministic
SID/rule-id allocation, `content` byte encoding, ATT&CK extraction, traceability,
and artifact construction); each renders its own engine-specific syntax on top.
The framework is reused verbatim (`DetectionRegistry`, `DetectionPackage`,
`DetectionArtifact`, `TemplateRegistry`, `compute_artifact_id`).

## Supported mappings

Rules are emitted only for network-observable subjects (malicious IP / domain /
URL — covering C2, callback, download, and distribution hosts):

| Subject | Suricata | Snort (2.9) | Category |
|---|---|---|---|
| `ipv4` / `ipv6` | `alert ip $HOME_NET any -> <ip> any` | same | network |
| `domain` | `alert dns … dns.query; content:"<domain>"` | `alert tcp … $HTTP_PORTS … content:"<domain>"; http_header` | dns |
| `url` | `alert http … http.host; content:"<host>"; http.uri; content:"<path>"` | `… content:"<host>"; http_header; content:"<path>"; http_uri` | http |

Each rule populates `msg`, `sid`, `rev:1`, `classtype:trojan-activity`,
`metadata`, `reference:url,…`, `priority` (from severity), `flow` (HTTP rules),
and deterministic `content` (domain/URL only; non-safe bytes encoded as `|HH|`,
e.g. a URL's `?`/`=` → `|3F|`/`|3D|`). Findings on the same IOC merge into one
rule (duplicate suppression), taking the max severity.

**Never emitted for:** file hashes, CVE/CWE/CAPEC, threat-actor-only or
technique-only findings, file-only findings, or informational findings. A finding
with no deterministic network observable (e.g. an unparseable URL) yields no rule
— per the philosophy, no rule beats a weak/speculative one. Rules never contain a
file hash.

## Rule philosophy

Simple, deterministic rules over observable network activity. No speculative
signatures, no protocol content beyond what the finding provides. The IP rule
carries no `content` (it matches the address); domain/URL rules carry only the
finding's own domain/host/path.

## SID allocation strategy

Deterministic, no randomness, timestamp-independent, no UUID4:

```
sid = 1_000_000 + (sha256("<engine>|<kind>|<value>") mod 9_000_000)
```

The `sid` is **stable per IOC per engine** (a given IOC always maps to the same
Suricata SID and the same — distinct — Snort SID) and lands in the custom/local
SID range `[1_000_000, 10_000_000)`. The ThreatLens `rule_id`
(`sur_…`/`snr_…`) and framework `detection_id` (`det_…`) are likewise stable;
network rules contain no date, so identity is naturally timestamp-independent.

## Traceability

Every rule's `metadata:` carries `threatlens_version`, `rule_id`,
`detection_id`, `created_from investigation_summary`, one `finding_id` per source
finding, sources, and `mitre_attack` techniques; `reference:url` cites MITRE
ATT&CK plus a ThreatLens link. The `DetectionArtifact` mirrors this in structured
`metadata`/`references`. No rule exists without full provenance.

## Relationships

- **With Sigma:** an IP/domain/URL finding yields a Sigma rule (host/SIEM
  telemetry) *and* Suricata/Snort rules (wire/IDS) — complementary vantage points.
- **With YARA:** disjoint by design — YARA covers file hashes; these cover network
  indicators. A hash finding produces YARA (+ Sigma), never a network rule.
- **With InvestigationSummary:** strictly downstream and read-only; never
  influences findings, confidence, severity, priority, recommendations, or
  relationships. The Reasoning Engine remains the only source of truth.

## Limitations

- IP/domain/URL only; no port/protocol-specific logic beyond the standard
  headers. No `content` beyond the indicator itself (no speculative byte patterns).
- Snort output targets 2.9-style syntax (`http_header`/`http_uri` modifiers);
  Suricata uses modern sticky buffers (`dns.query`/`http.host`/`http.uri`).
- No rule compilation/validation (`UNVALIDATED`; a later phase).

## Example rules

Suricata (malicious IP):
```
alert ip $HOME_NET any -> 45.155.205.233 any (msg:"ThreatLens: Malicious IP address 45.155.205.233"; classtype:trojan-activity; reference:url,attack.mitre.org/techniques/T1071/001/; reference:url,github.com/Otomen1/ThreatLens; metadata:threatlens_version 1.0.0, rule_id sur_d534f5ac489b55a9, detection_id det_2e2399ac99b84db0, created_from investigation_summary, finding_id fnd_…, source abuseipdb, mitre_attack T1071.001; priority:1; sid:5724379; rev:1;)
```

Snort (malicious domain):
```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ThreatLens: Malicious domain evil.net"; flow:to_server,established; content:"evil.net"; http_header; nocase; classtype:trojan-activity; reference:url,github.com/Otomen1/ThreatLens; metadata:threatlens_version 1.0.0, rule_id snr_…, detection_id det_…, created_from investigation_summary, finding_id fnd_…; priority:1; sid:…; rev:1;)
```

## Testing & performance

`backend/tests/test_network_generators.py` (24 tests, both engines
parametrized): registration, IP/domain/URL mappings + `content` byte encoding,
rejection of every non-network subject, structure + traceability, determinism,
stable/engine-distinct SIDs in the documented range, duplicate suppression,
serialization, golden snapshots (Suricata + Snort IP), and the API contract.
Frontend helper tests cover the `.rules` filename. The Reasoning Engine and its
golden suites are untouched.

Combined Suricata + Snort generation is linear (~34 µs/rule): **1 finding ≈
0.07 ms, 10 ≈ 0.69 ms, 50 ≈ 3.4 ms, 100 ≈ 6.7 ms** (2 rules per finding).
