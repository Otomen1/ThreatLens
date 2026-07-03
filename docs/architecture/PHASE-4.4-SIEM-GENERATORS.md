# Phase 4.4 — SIEM Detection Generators

## Status

Five platform-native SIEM generators for the Detection Engineering Framework,
registered in `build_default_registry()` alongside Sigma, YARA, Suricata, and
Snort (nine generators total). No engine change, no API change:
`POST /api/v1/detections` may now return Splunk + Sentinel + Elastic + Chronicle
+ QRadar artifacts. No AI, no Sigma conversion, no other generators.

| Generator | Platform | Language |
|---|---|---|
| `SplunkGenerator` | Splunk Enterprise Security | SPL |
| `SentinelGenerator` | Microsoft Sentinel | KQL |
| `ElasticGenerator` | Elastic Security | ES\|QL |
| `ChronicleGenerator` | Google Chronicle | YARA-L 2.0 |
| `QRadarGenerator` | IBM QRadar | AQL |

## Architecture

Each generator is an independent, pure `DetectionGenerator` that reads **only**
`Finding` objects — no providers, raw TI, WHOIS, NVD/MITRE JSON, network, or wall
clock. They **generate native syntax directly** (never Sigma converted). A new
pure helper module, `future/_siemcommon.py`, is shared for observable
classification, deterministic identity, value escaping, the provenance-metadata
builder, parser-level validation, and artifact construction; each generator owns
its platform query bodies. The framework is reused verbatim (`DetectionRegistry`,
`DetectionPackage`, `DetectionArtifact`, `TemplateRegistry`,
`compute_artifact_id`).

Two new `DetectionLanguage` values were added (the enum documents itself as
"extended as generators land"): `elastic_esql`, `chronicle_yara_l`, `qradar_aql`
(Splunk/Sentinel already existed).

## Detection eligibility & mappings

SIEM detections are generated for log-observable subjects only:

| IOC | Splunk field | Sentinel table/field | Elastic ECS | Chronicle UDM | QRadar |
|---|---|---|---|---|---|
| IP | `src_ip`/`dest_ip` | `CommonSecurityLog` IPs | `source.ip`/`destination.ip` | `principal.ip`/`target.ip` | `sourceip`/`destinationip` |
| Domain | `query`/`url` | `DnsEvents.Name` | `dns.question.name` | `network.dns.questions.name` | payload `ILIKE` |
| URL | `url` | `RequestURL` | `url.original` | `target.url` | payload `ILIKE` |
| Hash | `md5`/`sha1`/`sha256` | `DeviceFileEvents` | `file.hash.*` | `target.file.*` | payload `ILIKE` |
| Process | `process_name` | `DeviceProcessEvents` | `process.name` | `target.process.file.full_path` | payload `ILIKE` |
| Registry | `registry_path` | `DeviceRegistryEvents` | `registry.path` | `target.registry.registry_key` | payload `ILIKE` |
| PowerShell | `ScriptBlockText` | `ProcessCommandLine` | `process.command_line` | `target.process.command_line` | payload `ILIKE` |

**Not generated for:** CWE, CAPEC, threat-actor-only or technique-only findings,
informational findings, malformed hashes, or unsupported entity types (a bare
technique/actor has no queryable value; its ATT&CK id still enriches the
metadata of the IOC detections). Findings on the same IOC merge into one query.

## Metadata & determinism

Every detection carries full provenance both in the `DetectionArtifact.metadata`
and embedded in the query (as a comment header for SPL/KQL/ES|QL/AQL, or the
`meta:` block for YARA-L): **detection id, generator, platform, finding ids,
severity, confidence (score + band), MITRE mappings, IOC type/value, generated
timestamp, engine version**, and the ThreatLens rule id.

Determinism: identical `InvestigationSummary` → identical query. Identifiers hash
only stable values (platform, IOC kind, value) — no randomness, no UUIDs. The
query **body** is the identity; the `generated_at` timestamp (inherited from the
summary, never the wall clock) and the detection id live only in the provenance
metadata and are **excluded from the identity hash**, so ids are stable across
executions and the package id stays timestamp-independent.

## Validation

Native SIEM validators are unavailable, so each artifact is **parser-level
validated** (`validator: threatlens-parser`): required-token checks per language
(e.g. `index=` for SPL, `FROM`/`WHERE` for ES|QL, `rule`/`events:`/`condition:`
for YARA-L) plus brace-balance (outside strings) for YARA-L. Generated content
passes as `VALID`; a structural defect would surface as `INVALID`.

## Relationships

- **With Sigma/YARA/Suricata/Snort:** independent, coexisting generators. A single
  investigation now yields complementary detections across up to nine formats —
  e.g. a malicious IP produces Sigma + Suricata + Snort + all five SIEM queries; a
  hash produces YARA + all five SIEM queries.
- **With InvestigationSummary:** strictly downstream and read-only; never
  influences findings, confidence, severity, priority, recommendations, or
  relationships. The Reasoning Engine remains frozen.

## Frontend

The Detection Engineering panel already renders any artifact (language, title,
severity, category, finding IDs, source, copy, download); Phase 4.4 adds the three
new languages to the client type and native download extensions
(`.spl`, `.kql`, `.esql`, `.yaral`, `.aql`) so analysts can export all nine
formats. Read-only.

## Generated examples

Splunk SPL (malicious process):
```
```
ThreatLens Detection
detection_id: det_…
platform: Splunk Enterprise Security
finding_ids: fnd_…
severity: high
mitre: T1059
ioc: process=powershell.exe
generated_at: 2024-06-01T12:00:00Z
engine_version: 1.0.0
```
index=* process_name="powershell.exe"
| stats count by host, user, process_name, parent_process_name
```

Chronicle YARA-L (malicious IP):
```
rule threatlens_chr_…
{
    meta:
        author = "ThreatLens Detection Engine"
        detection_id = "det_…"
        severity = "critical"
        mitre = "T1071.001"
        ioc = "ip=45.155.205.233"
        engine_version = "1.0.0"
    events:
        $e.principal.ip = "45.155.205.233" or $e.target.ip = "45.155.205.233"
    condition:
        $e
}
```

QRadar AQL (malicious domain):
```
/* … provenance … */
SELECT QIDNAME(qid) AS event, sourceip, destinationip, UTF8(payload) AS payload FROM events WHERE UTF8(payload) ILIKE '%evil.example.net%' LAST 7 DAYS
```

## Limitations

- One detection per IOC; no correlation, aggregation, or lookups. Field/table
  choices are standard defaults, not tuned per deployment schema.
- QRadar non-IP IOCs use a payload contains-match (portable across log sources).
- Parser-level validation only — not full native compilation (a later phase could
  add real validators).

## Testing & performance

`backend/tests/test_siem_generators.py` (parametrized across all five platforms):
registration, every supported IOC type with native-syntax + validation checks,
rejection of unsupported subjects, complete metadata, determinism,
timestamp-independent stable ids, package-id stability, serialization, golden
snapshots (id + content hash per platform), and the API contract. Frontend helper
tests cover the five new extensions. The Reasoning Engine and its golden suites
are untouched.

Combined five-platform generation is linear (~29 µs/rule): **1 finding ≈ 0.18 ms,
10 ≈ 1.5 ms, 50 ≈ 7.2 ms, 100 ≈ 14.4 ms** (5 rules per finding).
