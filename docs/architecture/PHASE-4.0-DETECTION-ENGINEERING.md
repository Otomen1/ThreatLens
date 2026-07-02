# Phase 4.0 — Detection Engineering Framework

## Status

**Framework only.** This phase introduces the Detection Engineering Framework —
the pure engine, canonical models, content-addressed identity, an (empty)
generator registry, template infrastructure, and validation extension points. It
ships **no generators**: no Sigma, no YARA, no SIEM/EDR content, no AI, no rule
generation. Those arrive in later phases (see `detection/future/`).

## Position in the platform

The Detection Engine is a new **downstream consumer** of the frozen
`InvestigationSummary`, alongside the AI Explanation layer. It sits at the end of
the pipeline and feeds nothing back into it:

```
Threat Intelligence ─┐
Knowledge Intelligence ─┤→ Investigation → Reasoning Engine → InvestigationSummary ─┬→ AI Explanation
                     ─┘        (frozen, the only source of truth)                   └→ Detection Engine → DetectionPackage
```

The `InvestigationSummary` is the permanent contract. The Detection Engine is a
**pure consumer**: it never performs investigations, contacts providers, calls
AI, reads the wall clock, or modifies **findings, confidence, severity, priority,
recommendations, or relationships**. Severity is *copied* from findings, never
recomputed.

## Package layout

```
backend/src/threatlens/detection/
├── __init__.py       # public API + __all__
├── types.py          # enums (language, category, severity, capability, validation status)
├── models.py         # frozen canonical models (DetectionPackage, DetectionArtifact, …)
├── engine.py         # DETECTION_ENGINE_VERSION, generate(), content-addressed ids
├── registry.py       # DetectionGenerator/DetectionValidator ABCs + DetectionRegistry
├── templates.py      # DetectionTemplate registry + apply_template() helper
├── config.py         # DetectionSettings (env-driven seam)
└── future/           # reserved namespace for later generators (no implementations)
```

The design mirrors the Reasoning Engine and the provider frameworks: a pure
function behind a versioned constant, immutable models, a small explicit registry
with no global mutable state, and content-addressed identity.

## Canonical models

All models are frozen and fully typed; sequence fields are tuples so a package is
immutable after construction.

| Model | Purpose |
|---|---|
| `DetectionPackage` | Top-level output: content-addressed `id`, `metadata`, `artifacts`, `languages`, `references`, `source_finding_ids`. `is_empty` when no artifacts. |
| `DetectionArtifact` | One generated detection: `id`, `language`, `target`, `title`, `content` (rule text, empty this phase), `severity` (copied), `category`, `capabilities`, `source_finding_ids`, `references`, `validation`, `rule_id`, `metadata`. |
| `DetectionMetadata` | Provenance: `engine_version`, `source_engine_version`, entity, `generated_at` (inherited from the summary), `source_finding_count`, `source_posture`. |
| `DetectionTarget` | Where an artifact runs: `language` + `platform`/`product` (or `generic`). |
| `DetectionTemplate` | Reusable blueprint fixing language/target/category so artifacts are shaped and identified consistently. |
| `DetectionReference` | A citation (MITRE technique, CVE, vendor doc). |
| `DetectionValidation` | Validation outcome; `UNVALIDATED` in this phase. |

Enums (`types.py`): `DetectionLanguage`, `DetectionCategory`, `DetectionSeverity`
(ordinal, value-aligned with reasoning `Severity`), `DetectionCapability`,
`DetectionValidationStatus`.

## The engine

`generate(summary, *, registry=None) -> DetectionPackage` is a **pure function**:

- Runs each registered generator, collects artifacts, orders them deterministically
  (most severe first, then language, then id).
- Inherits `generated_at` from the summary — it never reads the wall clock, so
  identical input always yields an identical package.
- Copies `source_posture` and `source_finding_ids` from the summary for context.
- With the default (empty) registry, returns a well-formed, artifact-free package.

### Identity

Every detection gets a deterministic, content-addressed id that hashes **only
stable values** — never timestamps, never AI output:

- `compute_artifact_id` → `det_` + `sha256(language | platform | category |
  content | rule_id | sorted(source_finding_ids))[:16]`.
- `compute_package_id` → `pkg_` + `sha256(entity | source_engine_version |
  sorted(artifact_ids) | sorted(source_finding_ids))[:16]` — **excludes
  `generated_at`**, so re-running detection on the same investigation at a
  different time yields the same package id.

## Registry & extension points

`DetectionRegistry` holds `DetectionGenerator` instances keyed by unique name,
exposed in deterministic `(priority, name)` order.
`build_default_registry()` returns an **empty** registry — the single wiring point
future phases register generators into (exactly as `providers.defaults` wires
providers).

Two ABCs define the seams for later phases; **neither has a concrete
implementation yet**:

- `DetectionGenerator` — `generate(summary) -> Sequence[DetectionArtifact]`. Pure:
  no I/O, no providers, no AI, never mutates the summary.
- `DetectionValidator` — `validate(artifact) -> DetectionValidation`. The seam for
  Sigma syntax, YARA compilation, Suricata/Snort parsing, Sentinel KQL, and
  Splunk SPL validation.

`templates.apply_template(template, …)` is the single, tested path a generator
uses to turn finding-derived content into a content-addressed artifact, so adding
a generator never re-derives identity or artifact shape.

## Configuration

`DetectionSettings.from_env()` reads `DETECTION_ENABLED` (default `true`) and
`DETECTION_LANGUAGES` (comma-separated; default none). It is a seam for selecting
generators in later phases; it gates nothing yet (the empty registry is the
control).

## API

```
POST /api/v1/detections
  body:     InvestigationSummary        (the deterministic /investigate output)
  response: DetectionPackage            (empty/artifact-free in this phase)
```

The endpoint is a pure consumer with no access to providers or AI. It always
returns `200` with a well-formed package; a malformed body is rejected with `422`.
The route and contract exist now so future generators light up with no API change.

## Frontend

`lib/api.ts` gains the full `DetectionPackage` type set and `generateDetections()`.
`components/investigation/DetectionEngineeringCard.tsx` is a collapsed, downstream
panel (mirroring the AI card) that lazily fetches the package on expand and shows
**“No detection artifacts generated.”** The UI already understands a
fully-populated package (artifact rows, language badges, ids); rule rendering
arrives with the generators.

## Testing

`backend/tests/test_detection_engineering.py` (24 tests) covers:

- **Purity** — `generate()` does not mutate the summary; identical input → equal
  output.
- **Determinism & identity** — stable ids; `pkg_` id is timestamp-independent;
  `det_` id is content-addressed and finding-order-independent.
- **Registry** — register/get/duplicate/order; default registry empty.
- **Templates** — registry + `apply_template` shape/identity.
- **Pipeline** — a fake generator drives registry → engine → package end-to-end.
- **Serialization/immutability** — JSON round-trip; frozen models.
- **Config** — env parsing.
- **API contract** — empty package, HTTP determinism, `422` on bad input, and that
  detection never alters the investigation.

Frontend `lib/api.test.ts` covers the `generateDetections` client (URL/method/body,
empty package, abort, non-2xx). The reasoning golden regression suites are
unchanged — the frozen engine is untouched.

## Future generators (`detection/future/`)

Later phases add one subpackage per language, each a pure `DetectionGenerator`
registered in `build_default_registry`: `sigma`, `yara`, `suricata`, `snort`,
`splunk` (SPL), `sentinel` (KQL), `elastic` (EQL), `crowdstrike`,
`trend_vision_one`, `stellar_cyber`. None exist yet.
