# ThreatLens Backend

Python backend for ThreatLens. See `../docs/architecture/PHASE-0-ARCHITECTURE.md`
for the overall design.

## Phase 1.1 — Universal Entity Detection Engine

Deterministic, AI-free, network-free classification of arbitrary input into a
normalized `Entity`. Given any string, the engine identifies what it represents
(IPv4/IPv6, domain, URL, email, hash, CVE, MITRE technique, registry key,
process, PowerShell command, Windows API, threat actor, malware family) or
falls back to `FREETEXT` / `UNKNOWN`.

```python
from threatlens.search import detect

detect("185.100.10.15")        # -> Entity(type=ipv4, confidence=100, ...)
detect("hxxp://evil[.]com/x")  # -> Entity(type=url, normalized_value="http://evil.com/x")
detect("Cozy Bear")            # -> Entity(type=threat_actor, normalized_value="APT29")
```

### Layout

| Path | Responsibility |
|------|----------------|
| `entities/types.py` | `EntityType` / `ValidationStatus` vocabularies |
| `entities/models.py` | The `Entity` output contract (Pydantic) |
| `entities/reference/` | Curated soft-type reference data (actors, malware, APIs, processes, PowerShell) |
| `search/normalize.py` | Defang/refang + cleanup |
| `search/detectors/` | One detector per entity type (the extension seam) |
| `search/registry.py` | Priority-ordered detector registry |
| `search/classifier.py` | The detection engine |

Adding an entity type = add a detector class + one line in
`search/detectors/__init__.py`. No existing detector or the engine changes.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest          # 97 tests
ruff check src tests
```

Runtime dependencies: `pydantic`, `tldextract` (configured for offline use of
its bundled Public Suffix List snapshot — no network at runtime).
