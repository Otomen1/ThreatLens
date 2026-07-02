# ThreatLens Backend

Python backend for ThreatLens Core Platform v1.0 — detection, providers,
knowledge, reasoning, and the AI explanation layer behind the FastAPI service.
See the [root README](../README.md) for the platform overview and
`../docs/architecture/` for design references.

## Package layout

| Package | Responsibility |
|---------|----------------|
| `entities/` | `EntityType` vocabulary, the `Entity` contract, soft-type reference data |
| `search/` | Universal Entity Detection Engine (normalize → detectors → classifier) |
| `providers/` | Threat-intelligence framework + providers (AbuseIPDB, OTX, URLhaus, MalwareBazaar), aggregation |
| `reference/` | Knowledge framework + bundled providers (MITRE ATT&CK, NVD, CWE, CAPEC) |
| `investigation/` | Concurrent TI + knowledge investigation service |
| `reasoning/` | **Reasoning Engine v1.0 (frozen)** — evidence, findings, confidence, priority, recommendations |
| `ai/` | Downstream AI explanation layer (Ollama first; disabled by default) |
| `api/` | FastAPI app: `/api/v1/detect` · `/api/v1/investigate` · `/api/v1/explain` |

Adding an entity type = add a detector class + one registry line. Adding a
provider = declare metadata, return the canonical `IntelligenceResult`,
register it in `defaults.py`. The reasoning engine only changes deliberately —
its output is pinned by golden snapshots (`tests/benchmark/`,
`tests/validation/`).

```python
from threatlens.search import detect

detect("185.100.10.15")        # -> Entity(type=ipv4, confidence=100, ...)
detect("hxxp://evil[.]com/x")  # -> Entity(type=url, normalized_value="http://evil.com/x")
detect("Cozy Bear")            # -> Entity(type=threat_actor, normalized_value="APT29")
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                     # full suite — offline, no keys, no model
ruff check src tests
mypy src/threatlens        # strict
uvicorn threatlens.api.app:app --reload
```

Configuration is environment-driven and entirely optional — copy
`.env.example` to `.env` for provider keys. Everything except live external TI
and AI inference runs offline (bundled datasets; `tldextract` uses its bundled
Public Suffix List snapshot).
