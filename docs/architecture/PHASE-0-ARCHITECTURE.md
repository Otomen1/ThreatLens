# ThreatLens — Phase 0: Software Architecture & Technical Specification

## Context

`otomen1/threatlens` is a greenfield repository (only `README.md` + a Python `.gitignore`). The owner wants a production-quality architecture for an **AI-powered Threat Intelligence & Detection Engineering Platform**.

**Architectural pivot (this revision):** the platform is designed around a **Universal Search Engine as its core subsystem**, not an IOC-analysis pipeline. **Every feature in ThreatLens begins with Search.** A user searches almost anything; the search engine automatically identifies the **entity type** (IOC, Malware Family, Threat Actor, CVE, MITRE Technique, Windows API, Process, Registry Key, …), routes the request to the appropriate **intelligence sources**, federates and correlates the results, and uses AI to *explain and synthesize* — never to parse or to apply a binary "malicious" label. **IOC analysis is one capability of the search engine**, alongside reference-knowledge lookup and (later) uploaded-report and internal-knowledge-base search.

This is the Phase 0 deliverable: a full architecture review plus a critical self-review. **No code is written.** Three foundational constraints were confirmed with the owner and shape every section:

1. **Deployment/tenancy:** Self-hosted, single-tenant (operator holds source API keys; design seams toward SaaS later).
2. **Scale/team:** Solo / small team, lean (modular monolith, managed services, Docker-first).
3. **Stack:** Python (FastAPI) backend + Next.js/React (TypeScript) frontend.

> **Execution note (post-approval):** this specification is committed to the repo at `docs/architecture/PHASE-0-ARCHITECTURE.md` on branch `claude/magical-knuth-lih9s1`. No application code is created in this phase. See "Execution & Verification" at the end.

---

## 1. Executive Review

ThreatLens's organizing idea is **"every detection begins with understanding the indicator,"** and the sharpest expression of that idea is to make **Search the universal front door and core subsystem.** A user asks about *anything* — an IP, a hash, `emotet`, `T1059.001`, `rundll32.exe`, `CVE-2024-3094` — and the system recognizes what it is, knows where to look, gathers and correlates intelligence, and explains it. IOC enrichment is then simply the search capability that handles IOC-typed entities, sitting beside reference-knowledge lookup today and report/knowledge-base search tomorrow.

This Search-first framing is the right core for three reasons. **First, it matches the stated long-term vision** — "Universal search" is literally the first capability listed, and reports, knowledge base, and detection generation all naturally become *sources for* or *consumers of* search rather than separate apps. **Second, it is more extensible:** every future feature plugs into one well-defined seam (a search source or a search consumer) instead of bolting onto a rigid IOC pipeline. **Third, it generalizes the parts that were already strong** — the deterministic type-detector becomes a universal **entity classifier**; the TI-provider plugin becomes a universal **search-source plugin**; the evidence-first verdict becomes one kind of **search result**.

Two principles from the brief survive the reframe and remain non-negotiable: (a) **deterministic work is separated from AI work** — classification, routing, and source queries are mechanical and reproducible; explanation, correlation, and MITRE mapping are the LLM's job; and (b) **results are evidence-first and never binary** — `powershell.exe` → "Legitimate Process Frequently Abused," not "malicious."

**My judgment: approve the Search-as-core architecture, approve a deliberately lean Phase 1, and reject building the knowledge graph, search cluster, or microservices now.** The principal risks shift slightly under this framing: beyond the original concerns (third-party rate limits/ToS, soft-type detection, prompt injection), the Search-first design adds **relevance/ranking across heterogeneous sources** and **over-abstraction** as real risks (§3, §27). With the mitigations below — and a Phase 1 that ships a *fully real* IOC + reference search, not an abstract framework — this is a sound multi-year foundation. I also reiterate one model-level recommendation: **align the entity model with STIX 2.1 and MISP interop now** (§7); it is nearly free here and makes search across reports, KB, and the future graph coherent.

---

## 2. Strengths of This Idea

- **Search as the unifying abstraction.** One mental model, one entry point, one extension seam. Every roadmap item (reports, KB, relationship graph, detection generation) becomes a *source for* or *consumer of* search rather than a bespoke subsystem.
- **Automatic entity identification.** "Search anything" with no type dropdown is a major UX advantage and the natural generalization of the IOC detector to all entity types.
- **Source-agnostic federation.** TI providers, reference knowledge (MITRE/CVE/malware/actor), the internal KB, and uploaded reports all answer the same `SearchSource` contract — heterogeneous intelligence behind one interface.
- **Deterministic/AI separation, preserved and generalized.** The classifier and source routing are deterministic and testable; AI synthesizes over results. Reproducible, auditable.
- **Evidence-first, non-binary results.** Mirrors analyst mental models; builds trust; avoids credibility-destroying false positives.
- **Cross-entity navigation falls out for free.** A search for an IP surfaces a related malware family, which is itself a searchable entity — pivoting between entities is intrinsic to a search core.
- **Stack fit.** Python owns the TI/ML/security ecosystem (`validators`, `tldextract`, `stix2`, `pymisp`, ATT&CK data, `yara-python`); React/Next owns the UI.

## 3. Weaknesses

- **Ranking/relevance across incomparable sources is genuinely hard.** A reputation score from VirusTotal, a MITRE technique description, and a snippet from an uploaded report are not on the same scale. Naïve federation produces a jumbled result set. This is the central new challenge of the Search-first design and must be designed deliberately (§13).
- **Over-abstraction risk.** "Everything is search" can decay into a generic framework that does nothing concretely well. Phase 1 must ship *fully functional* IOC + reference search, not an empty orchestration layer.
- **"Soft" entity types resist deterministic detection.** Malware family, threat actor, process name, Windows API, PowerShell command, and file name cannot be reliably identified by regex/validators. These are *classification by reference-data lookup + heuristics*, not parsing — and may need user disambiguation. The "AI never detects" rule must be stated precisely (§27): AI never detects *structured* entities; soft types use curated reference data with explicit confidence.
- **Free-tier source rate limits are brutal.** VirusTotal public ≈ 4 req/min / 500/day; AbuseIPDB ≈ 1,000/day. Federated fan-out multiplies pressure across sources. Caching, key management, and streamed partial results are mandatory.
- **Source Terms of Service constrain caching/redistribution.** Several feeds restrict cache duration and prohibit re-serving data. This affects the database and any future SaaS; tracked per-source (§14, §27).
- **Scoring/relevance calibration is high-risk.** A miscalibrated IOC band or a bad cross-source ranking erodes trust faster than no answer.
- **AI cost is unbounded without discipline.** Synthesis over federated results, run interactively, can balloon without caching, model routing, batching, and budgets.

## 4. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Poor cross-source ranking/relevance | High | High | Per-source-kind normalized result schema; deterministic, explainable ranking (source reliability × relevance × recency); group results by entity, never one flat list; iterate with an eval set |
| Source rate-limit exhaustion under federated fan-out | High | High | Multi-layer caching (§16), per-source Redis token buckets, async streamed partial results, configurable key sets, "cached vs fresh" UX |
| Over-abstraction / framework-with-no-product | Medium | High | Phase 1 ships real IOC + reference search end-to-end; abstractions justified only by ≥2 concrete sources; YAGNI enforced |
| Prompt injection via source content (WHOIS, tags, report bodies) | High | High | Treat all source text as untrusted *data*; delimit/label in prompts; model never follows embedded instructions; structured outputs; no side-effecting AI tools in Phase 1 |
| Source ToS violation (cache/redistribution) | Medium | High (legal) | Per-source policy registry; honor TTL/redistribution flags; single-tenant operator-key model; legal review before SaaS |
| Miscalibrated IOC confidence band → false trust | Medium | High | Transparent, versioned, explainable scoring; show evidence not just a number; "insufficient data" is valid; calibration eval set |
| SSRF via URL/domain sources and future report-fetch | Medium | High | Deny private/link-local/metadata ranges; allowlist schemes; resolve-then-validate; egress controls |
| AI hallucinated reputation/relationships | Medium | High | Ground strictly in retrieved results; require citations; AI explains deterministic outputs, doesn't invent them |
| LLM/source cost overrun | Medium | Medium | Model routing (Haiku triage / Opus depth), prompt caching, Batch API, token/$ budgets + circuit breakers |
| Over-engineering (graph DB, search cluster, microservices early) | Medium | Medium | Postgres-first; documented extraction seams only |
| Single-node self-host outage / data loss | Medium | Medium | Healthchecks, automated `pg_dump` backups, restore runbook |

## 5. Scalability Concerns

For the chosen target (self-hosted, single-tenant, small team) raw scale is not the near-term problem — **the Search Orchestrator's federated fan-out is the hot path, and source latency + rate limits are the constraint.**

- **The bottleneck is outbound I/O across many sources.** The orchestrator fans out with `asyncio.gather` over `httpx`, per-source timeouts and circuit breakers. App CPU and DB are nearly idle by comparison. Async-first FastAPI is the right primitive.
- **Cache hit ratio is the dominant lever.** A warm cache turns a multi-source, multi-second federation into a sub-200 ms read. Invest here first.
- **Ranking/aggregation is cheap;** federation latency dominates. Keep aggregation in-process; don't prematurely externalize.
- **Vertical-first.** One modern node (Postgres + Redis + API + worker) serves a team comfortably. No sharding/clustering until measured.
- **Designed seams for SaaS scale:** the **Search Orchestrator** and the **AI synthesis service** are the two natural first extractions (both I/O-bound, independently scalable, clean interfaces). The source-plugin registry and the queue boundary make extraction a config change, not a rewrite.
- **Data growth is modest and TTL-bounded.** Hot results in Redis expire; durable normalized history in Postgres grows with distinct entities and is time-partitionable later. pgvector embeddings (future report/KB search) are the main growth vector to watch.

## 6. Missing Features (gaps in the brief to plan for)

- **Bulk / batch search** (paste many entities, upload a CSV) — analysts rarely have exactly one.
- **Defang/refang** on input *and* output (`hxxp`, `[.]`, `(dot)`) — table stakes; safe rendering of malicious values.
- **Cross-entity pivoting** — every related entity in a result is a one-click new search (core to a search product).
- **Saved searches & search history with shareable permalinks** — revisit and cite a result.
- **Export** (STIX 2.1, MISP JSON, CSV, Markdown) — portable output; cheap if the model is STIX-aligned (§7, §12).
- **"Refresh / re-search"** to bypass cache deliberately.
- **Audit log** — who searched what, when.
- **Source health dashboard** — which sources are up; rate-limit budget remaining.
- **Confidence/age transparency** — surface result staleness and source reliability.
- **API tokens for automation** — scriptable search; the seam for SOAR/SIEM integration.
- **MISP / OpenCTI interop** (§7).

## 7. Better Product Direction (recommendations that change the design)

1. **Make Search the product's identity and its primary API.** "Search anything in threat intel, understand it instantly." The single search box *is* the product; every capability is reachable through it. This is a sharper position than "another TIP."
2. **Adopt STIX 2.1 as the internal entity model and MISP as the interop target — now.** Entities map cleanly to STIX SDOs/SROs (Indicator, Malware, Threat-Actor, Attack-Pattern, Vulnerability, Relationship). STIX-shaping the model at Phase 1 makes federated results, cross-entity correlation, export, and the future graph nearly free. Highest-leverage recommendation.
3. **Position alongside, not against, MISP/OpenCTI.** Those are systems of record; ThreatLens is a fast *search-understand-explain* layer that can ingest from and export to them — even treat them as **search sources**.
4. **Make AI synthesis cite its sources.** Every AI claim links to the search result that supports it. Auditability is the moat versus generic "ask an LLM about this IP" tools.
5. **Treat reports, knowledge base, and detection generation as search sources/consumers, not separate apps.** Uploaded reports and the KB become *additional sources* the orchestrator federates over; YARA/Sigma generators become *consumers* of the entity model search produces. This is the cleanest path through the whole roadmap.
6. **Keep Phase 1 ruthlessly concrete.** Universal classifier + source routing + IOC sources + reference-knowledge sources + scoring + AI synthesis + history. Defer report/KB sources, graph, and search cluster — but ship IOC + reference search *fully*.

## 8. Recommended Technology Stack

**Backend**
- **Python 3.12+**, **FastAPI** (async), **Pydantic v2** (validation, settings, structured-output schemas).
- **httpx** (async source I/O), **tenacity** (retry/backoff), custom circuit breaker.
- **SQLAlchemy 2.0** (async) + **Alembic** (migrations).
- **Arq** (async-native Redis task queue) for bulk/background search and (later) report ingestion. Celery is the fallback if richer routing is needed.
- **Classification/reference libs:** `ipaddress` (stdlib), `tldextract`, `validators`; curated reference data for soft entity types (MITRE ATT&CK STIX bundle, LOLBAS process list, malware/actor alias lists, NVD/CVE data).

**Datastores**
- **PostgreSQL 16** — durable store; JSONB for raw source payloads; **pgvector** provisioned for future semantic search over reports/KB (enable now, use later).
- **Redis 7** — result cache, per-source rate-limit token buckets, Arq broker (one instance, multiple roles in the lean setup).
- **Search index:** PostgreSQL full-text + trigram (`pg_trgm`) for Phase 1 history/reference/KB lookup. OpenSearch/Elasticsearch explicitly **deferred** until volume justifies it.

**AI**
- **Anthropic Claude** behind a thin, swappable LLM abstraction. **Claude Haiku 4.5** ($1/$5 per MTok) for fast triage and short syntheses; **Claude Opus 4.8** ($5/$25, 1M context) for deep cross-source correlation, MITRE mapping, and report-level synthesis (adaptive thinking + `effort` tuned per task); **Claude Fable 5** reserved for the hardest correlation only.
- **Structured Outputs** (`output_config.format` JSON schema) on every call — AI output is always schema-validated, never free-text-parsed.
- **Prompt caching** for the large static system prompt + reference context; **Batch API** for bulk synthesis (50% cost).

**Frontend**
- **Next.js (App Router) + React + TypeScript**, **TailwindCSS**, **shadcn/ui** (Radix).
- **TanStack Query** (server state/caching), **Zustand** (light client state).
- **Recharts/visx** for charts; **Cytoscape.js**/**React Flow** for the future relationship graph.
- **Server-Sent Events (SSE)** for progressive federated-result streaming.

**Platform / Ops**
- **Docker + Docker Compose** (single-node self-host), **Caddy** (TLS + reverse proxy).
- **structlog**, **Prometheus**, **OpenTelemetry** (wired early), **Sentry**.
- **GitHub Actions** CI/CD; **GHCR** images; **Ruff**, **mypy/pyright**, **pytest**; **Renovate/Dependabot**.

## 9. Backend Architecture

A **modular monolith** whose spine is the **Search Orchestrator**. One deployable, clean seams. IOC analysis is a capability invoked *by* search, not the core.

**The search pipeline (the spine of the system):**

```
Query (text / uploaded-ref / entity id)
  ─▶ Query Understanding  (defang/normalize · universal Entity Classification → candidates+confidence)
  ─▶ Source Routing       (entity type(s) → capable Sources via registry)
  ─▶ Federated Execution  (async fan-out to Sources; cache · timeout · circuit-breaker · rate-limit)
        Sources: External TI providers · Reference knowledge (MITRE/CVE/malware/actor)
                 · Internal KB (future) · Uploaded reports (future)
  ─▶ Aggregation · Correlation · Ranking
        (merge per entity · dedupe · cross-link related entities · rank by reliability×relevance×recency
         · for IOC entities, invoke deterministic Scoring → classification band)
  ─▶ AI Synthesis         (explain · correlate across sources · MITRE map · summarize · recommend; grounded+cited)
  ─▶ Unified Search Result (entity · classification · federated intelligence · AI synthesis ·
                            related entities · evidence · references · recommendations)
  ─▶ Persist · Cache · Stream (SSE)
```

**Modules (each a package with a public interface; no cross-reaching into internals):**
- `search/` — **the core.** Orchestrator, query understanding, **entity classifier** (deterministic), source router, aggregator/correlator/ranker. No network of its own beyond dispatching to sources; no AI.
- `sources/` — the pluggable **search-source** subsystem: `base.py` (`SearchSource` interface), `registry.py`, and source implementations grouped by kind:
  - `sources/external/` — TI providers (VirusTotal, AbuseIPDB, URLhaus, OTX, MalwareBazaar, OpenPhish, PhishTank).
  - `sources/reference/` — MITRE ATT&CK, CVE/NVD, malware-family & threat-actor knowledge.
  - `sources/knowledge_base/` — internal KB (Phase 2; interface present now).
  - `sources/reports/` — uploaded-report search (Phase 2; interface present now).
- `enrichment/` — normalizers + the **IOC analysis capability** (external IOC sources + scoring), exposed to `search` as one capability. *Network-touching.*
- `scoring/` — deterministic, transparent, versioned evidence-weighted band for IOC entities. No AI.
- `ai/` — LLM abstraction, versioned prompts, structured-output schemas, model router, grounding/injection guards, result cache.
- `entities/` — entity model + universal classification reference data access.
- `models/` (ORM) + `schemas/` (API DTOs) + `db/`.
- `services/` — wires the search pipeline (the only place modules compose).
- `api/` — FastAPI routers, auth, error envelope, SSE.
- `workers/` — Arq tasks (bulk search, background refresh, future report ingestion).
- `core/` — config, logging, telemetry, security (SSRF guard, secrets).

**Key principles:** dependency flows inward toward `core`/`models`/`entities`; `search` and `scoring` are pure and synchronous-testable (sources mocked); `sources` and `ai` are the only network-touching modules; the synchronous request path streams fast-source results then AI synthesis, while slow sources and bulk run in `workers`.

## 10. Frontend Architecture

A search-centric analyst UI; the search box *is* the application.

- **One universal search box** as the primary surface. On submit: instant detected **entity type(s)** + confidence (with override for ambiguous/soft), then **progressively streamed** per-source results (SSE), then AI synthesis, then — for IOC entities — the scored verdict with evidence.
- **Entity-aware result rendering.** Result cards differ by entity type: an IOC shows Classification band · TI results · score+evidence; a MITRE technique shows description · tactics · procedures · detections; a malware family / threat actor shows a knowledge profile · aliases · related IOCs; a CVE shows CVSS · affected products · references. All share: AI synthesis (with citations), references, recommendations, and **related entities as clickable searches**.
- **Cross-entity pivoting** is first-class — related entities are links that launch new searches.
- **Progressive disclosure:** entity + synthesis first; raw source payloads behind expanders.
- **Routes (Next App Router):** `/` (search), `/entity/[type]/[id]` (permalink to a result), `/history`, `/sources` (health/budget), `/settings`.
- **State:** TanStack Query owns server cache + SSE merge; Zustand for ephemeral UI. SDK types generated from the backend OpenAPI schema so types never drift.
- **Safety in rendering:** all indicator values **defanged on display**; copy offers fanged/defanged; no auto-navigation to malicious URLs; external links guarded.
- **Accessibility & theming** via shadcn/Radix; dark mode default.

## 11. Database Design

PostgreSQL, normalized core with JSONB escape hatches; generalized from "indicator" to "entity." Conceptual tables (DDL deferred):

- `entities` — `id`, `type` (broad enum), `value` (normalized canonical), `value_raw`, `defanged`, `first_seen`, `last_seen`, `created_at`. **Unique `(type, value)`**; index on `type`; `pg_trgm` on `value` for fuzzy/reference search.
- `search_queries` — `id`, `raw_input`, `resolved_entity_id` (FK, nullable), `candidates` (JSONB), `user_id`, `created_at`. The search-history + audit spine.
- `search_results` — `id`, `query_id`, `entity_id`, `aggregated` (JSONB: ranked items + correlations), `created_at`. The federated, ranked result snapshot.
- `source_results` — `id`, `entity_id`, `source`, `kind`, `status` (ok/error/rate_limited/timeout/not_found), `raw` (JSONB), `normalized` (JSONB), `relevance`, `fetched_at`, `expires_at`. Index `(entity_id, source)`; GIN on `normalized`. (Generalizes per-provider enrichment to per-source results.)
- `assessments` — IOC-entity verdict: `entity_id`, `score`, `band` (enum), `summary`, `evidence` (JSONB[]), `references`, `recommendations`, `score_model_version`, `created_at`. Versioned/append-only.
- `ai_syntheses` — `entity_id`/`query_id`, `model`, `prompt_version`, `evidence_hash`, `summary`, `correlations` (JSONB), `mitre` (JSONB), `confidence_explanation`, `recommendations`, `token_usage`, `created_at`. Unique `(scope, evidence_hash, prompt_version, model)` → AI cache key.
- `relationships` — `src_entity_id`, `dst_entity_id`, `rel_type`, `source`, `confidence` (STIX SRO-shaped; powers cross-entity pivot + future graph).
- `sources` — registry metadata + ToS/retention flags (`cache_ttl_max`, `redistribute_allowed`, `kind`, supported types).
- `source_credentials` — encrypted-at-rest secrets (or pointer to env/secret store).
- `source_calls` — ledger for rate-limit accounting and cost/usage audit.
- `reference_*` — `malware_families`, `threat_actors` (+aliases), `processes` (LOLBAS), `windows_apis`, `mitre_techniques`, `cves` — backing soft-type classification *and* reference-knowledge sources.
- `documents` / `kb_entries` (Phase 2; pgvector embeddings) — report & KB sources.
- `users`, `api_tokens`, `audit_log`, `tags`.

**Conventions:** UUIDv7 PKs; `created_at/updated_at`; raw payloads in JSONB; promote hot fields to columns only when queried; Alembic for every change.

## 12. Entity Model

A **generalized Entity model**, STIX 2.1-aligned, with Indicator as one specialization:

- **Entity** (base) — typed, normalized value + provenance. The universal unit of search.
- **EntityType** (enum) — `IPV4, IPV6, DOMAIN, URL, EMAIL, MD5, SHA1, SHA256, CVE, MITRE_TECHNIQUE, MALWARE_FAMILY, THREAT_ACTOR, REGISTRY_KEY, WINDOWS_API, PROCESS_NAME, POWERSHELL_COMMAND, FILE_NAME, FREETEXT, UNKNOWN`. (IOC subtypes ⊂ all entity types.)
- **SearchQuery / SearchResult / SearchResultItem** — the search-core entities: a query resolves to candidate entities; a result aggregates ranked items from sources.
- **SearchSource** — a capability that answers certain entity types (TI provider, reference, KB, report). The universal plugin (§14, §17).
- **Assessment** (IOC entities) — deterministic verdict: score + **ClassificationBand** + evidence.
- **ClassificationBand** (enum) — `BENIGN, LIKELY_BENIGN, UNKNOWN, SUSPICIOUS, LIKELY_MALICIOUS, MALICIOUS` plus a **descriptive label** ("Legitimate Process Frequently Abused"). Never a bare boolean.
- **KnowledgeProfile** (non-IOC entities) — the result shape for malware/actor/technique/CVE: description, aliases, attributes, related entities.
- **Evidence** — `{source, statement, weight, supporting_data, reference}` — the atom of explainability, shared by scoring, ranking, and AI.
- **AISynthesis** — model's explanation/correlation/MITRE/recommendations, each tied to Evidence; carries reproducibility metadata.
- **Relationship** — typed edge (STIX SRO) enabling cross-entity pivot + future graph.
- **MalwareFamily / ThreatActor / AttackPattern / Vulnerability** — reference SDOs; both classification reference data and knowledge sources.
- **Source / Credential / User / ApiToken / AuditEvent / Tag** — operational entities.

## 13. Search Engine Architecture

**This is the core subsystem.** Everything else is a source for it or a consumer of it.

**(a) Query Understanding.**
- **Defang/normalize** (refang `hxxp`, `[.]`, `(dot)`; lowercase domains; canonicalize URLs; strip zero-width).
- **Universal Entity Classification (deterministic):** ordered, *validated* matchers, not loose regex — `ipaddress` (IPv4/IPv6); `tldextract` (domains); URL parser; length+charset (MD5/SHA1/SHA256); `CVE-\d{4}-\d{4,}`; `T\d{4}(\.\d{3})?` (ATT&CK); registry-key patterns; file-name/process heuristics.
- **Soft-type resolution** (malware/actor/process/API/PowerShell/file) via **reference-data lookup + heuristics**, returning candidates with confidence — *classification, not parsing*, and **never the LLM's job to detect** (§27).
- **Ambiguity & confidence:** return ranked candidate entities; user can override; `FREETEXT` falls through to reference/KB/report full-text search.

**(b) Source Routing.** Given resolved entity type(s), the **Source Registry** returns the capable sources (an entity-type → source matrix). Routing is policy-aware (respects per-source enable/auth/budget).

**(c) Federated Execution.** Fan out to selected sources concurrently with **per-source timeout, retry-with-backoff, circuit breaker, and rate-limit budgeting**; collect partial results; one slow/broken source never blocks the response. Cache-aware (§16).

**(d) Aggregation · Correlation · Ranking.**
- **Normalize** each source's payload into a common `SearchResultItem` shape.
- **Correlate**: link related entities discovered in results (an IP's results may name a malware family → create a Relationship → render as a pivot).
- **Rank** with a **deterministic, explainable** function: `source_reliability × relevance × recency`, grouped *per entity* (never one flat, incomparable list).
- **Score** (IOC entities only): invoke `scoring/` to produce the classification band + evidence as part of the result.

**(e) Streaming.** Results stream via SSE in the order they resolve (detection → per-source items → AI synthesis), so perceived latency ≪ total.

**(f) Extensibility.** Reports and the KB are added later **purely as new `SearchSource` implementations** — the orchestrator, classifier, ranker, and AI layer are unchanged. This is the payoff of the Search-first core.

## 14. Search Sources & Intelligence Architecture

The pluggable subsystem that answers searches — TI providers are **one kind** of source.

- **`SearchSource` interface:** `name`, `kind` (`external_ti | reference | knowledge_base | report`), `supported_entity_types`, `auth_schema`, `rate_limit`, `cache_ttl`, `tos_policy`, `async search(entity, context) -> list[SearchResultItem]`, `async health()`.
- **Source kinds (Phase 1 + designed-for):**
  - **External TI** — VirusTotal (hash/domain/IP/URL), AbuseIPDB (IP), URLhaus (URL/domain/hash), AlienVault OTX (most), MalwareBazaar (hash), OpenPhish + PhishTank (URL).
  - **Reference knowledge** — MITRE ATT&CK (techniques/tactics), CVE/NVD (vulnerabilities), malware-family & threat-actor knowledge. These answer the non-IOC entity types and supply soft-type classification data.
  - **Internal knowledge base** *(Phase 2)* — past results + curated notes (Postgres + pgvector).
  - **Uploaded reports** *(Phase 2)* — full-text + semantic search over ingested documents.
- **Entity-type → source matrix** lives in the registry and drives routing (§13b).
- **Normalization layer:** map each source's idiosyncratic payload into the common `SearchResultItem` (`title`, `summary`, `attributes`, `reputation?`, `relevance`, `source`, `fetched_at`, `related_entities`, `references`). Raw payload retained in JSONB.
- **Resilience & politeness:** Redis token-bucket rate limiting per source/key; conditional requests/ETags where supported; graceful degradation to cache; explicit `rate_limited`/`timeout` statuses surfaced to the UI.
- **Governance:** per-source **ToS/retention policy** in the registry (max cache TTL, redistribution allowed?) enforced by cache and any future export.

## 15. AI Architecture

AI **explains, correlates across sources, infers behavior, summarizes, maps MITRE, explains confidence, recommends.** It **never** classifies entity type, routes, parses, validates, or sets reputation.

- **LLM abstraction layer** (`LLMClient` interface) — default Anthropic Claude; swappable.
- **Model routing by task/cost:**
  - **Haiku 4.5** — fast structured triage and short per-entity syntheses.
  - **Opus 4.8** (1M context, adaptive thinking + `effort`) — deep **cross-source correlation**, MITRE mapping, confidence explanation, report-level synthesis.
  - **Fable 5** — hardest correlation only (cost-gated).
- **Operates over federated search results.** The signature job is **synthesis across heterogeneous sources** — reconciling agreement/disagreement, surfacing relationships, mapping to MITRE — exactly the value a search core unlocks.
- **Structured Outputs everywhere** (`output_config.format` JSON schema per task) → every AI response is schema-validated and storable. *We never regex/parse free-form model text.*
- **Grounding & anti-hallucination:** the model receives **only** the retrieved, normalized results + reference context; it cites each claim to a `SearchResultItem`/Evidence; outputs "insufficient evidence" rather than guess. AI annotates the **deterministic** outputs (band, ranking); it does not produce reputation or relevance.
- **Prompt-injection defense (critical):** all source/report text is attacker-controllable; wrapped in clearly delimited "untrusted data" blocks; the model is instructed to treat it as data and never follow embedded instructions; **no side-effecting tools** exposed in Phase 1; outputs schema-constrained.
- **Cost & reproducibility:** **prompt caching** of the large static system prompt + MITRE/reference context (≈90% savings on the cached prefix across the multi-step pipeline); **Batch API** for bulk (50% off); **AI result cache** keyed by `(scope, evidence_hash, prompt_version, model)`; per-request token caps; `$`/token budget + circuit breaker; every `AISynthesis` stores `model + prompt_version + evidence_hash`.

## 16. Caching Strategy

Caching is the make-or-break lever for federated search (§5).

- **L0 — in-process LRU:** classification results, reference-data lookups, source-routing decisions (microseconds).
- **L1 — Redis hot cache:** normalized source results keyed `source:type:value`, TTL per source policy; per-source rate-limit token buckets live here too.
- **L2 — Postgres durable store:** normalized `source_results` + `search_results` + `assessments` (audit, trend, ToS-bounded retention).
- **L3 — AI synthesis cache:** keyed by `evidence_hash + prompt_version + model`. Re-running synthesis on unchanged results costs nothing.
- **Invalidation:** TTL-driven; explicit **"Refresh / re-search"** bypasses L1/L3; prompt-version bump logically invalidates L3 (new key).
- **Stampede protection:** single-flight lock per `(source, value)` so N concurrent identical lookups make one upstream call.
- **Honesty in UX:** every result item shows source + fetched-at; "cached" vs "fresh" is visible.

## 17. Plugin Architecture

A general **plugin** model with the **`SearchSource`** as the primary extension point — the unifying seam for the whole roadmap.

- **Registration:** decorator/entry-point registry; each plugin declares metadata (name, kind, version, supported entity types, auth schema, rate limit, TTL, ToS policy, health).
- **Plugin kinds:** `SearchSource` (TI, reference, KB, report) is Phase 1's focus; the same lifecycle hosts `LLMProvider`, `Exporter` (STIX/MISP/CSV), `ReportParser` (Phase 2), and `DetectionGenerator` (YARA/Sigma, Phase 3+) — all register → configure → health → invoke.
- **Isolation & safety:** plugins run behind timeouts/circuit breakers; a misbehaving plugin degrades gracefully and is flagged in the source dashboard.
- **Config-driven:** enable/disable + credentials per plugin via settings; adding a source/key requires no code change.
- **Versioned interface:** a stable `SearchSource`/`BasePlugin` contract so community/third-party sources stay forward-compatible.

## 18. API Design

REST over FastAPI, versioned `/api/v1`, OpenAPI-generated (drives the TS client). **Search is the primary endpoint.**

- `POST /api/v1/search` — body `{query}` → `{search_id, candidates[], resolved_entity}` immediately; results stream via SSE.
- `GET /api/v1/search/{id}/stream` — **SSE**: emits `classification` → `source_result` (per source as it lands) → `correlation` → `ai_synthesis` → (`assessment` for IOC entities). The core UX primitive.
- `GET /api/v1/entities/{type}/{id}` — durable fetch for permalinks (entity + latest aggregated result).
- `POST /api/v1/search/bulk` — batched queries → background (Arq) job + status endpoint.
- `POST /api/v1/entities/{id}/refresh` — force re-search (cache bypass).
- `GET /api/v1/sources` — registry + health + rate-limit budget.
- `GET /api/v1/history`, `GET /api/v1/export/{id}?format=stix|misp|csv|md`.
- *(Phase 2)* `POST /api/v1/reports` — ingest a report as a search source.
- **Cross-cutting:** consistent error envelope `{error:{type,message,request_id}}`; cursor pagination; idempotency keys on writes; auth (session for UI, bearer token for automation); per-token rate limiting; request IDs in logs/traces.

## 19. Folder Structure

Monorepo. Backend uses a `src/` layout; `search/` is the core, `sources/` the extension surface.

```
threatlens/
├── backend/
│   ├── src/threatlens/
│   │   ├── core/                 # config, logging, telemetry, security (SSRF guard, secrets)
│   │   ├── entities/             # entity model helpers + classification reference-data access
│   │   ├── search/               # CORE: orchestrator, query understanding, classifier,
│   │   │                         #       router, aggregator/correlator/ranker
│   │   ├── sources/
│   │   │   ├── base.py           # SearchSource interface
│   │   │   ├── registry.py       # plugin registry + entity-type→source routing
│   │   │   ├── normalize.py
│   │   │   ├── external/         # virustotal.py, abuseipdb.py, urlhaus.py, otx.py, ...
│   │   │   ├── reference/        # mitre.py, cve.py, malware.py, actor.py
│   │   │   ├── knowledge_base/   # (Phase 2)
│   │   │   └── reports/          # (Phase 2)
│   │   ├── enrichment/           # IOC analysis capability (composes external IOC sources + scoring)
│   │   ├── scoring/              # deterministic IOC band (versioned)
│   │   ├── ai/                   # llm client, prompts/ (versioned), schemas, router, guards
│   │   ├── models/               # SQLAlchemy ORM
│   │   ├── schemas/              # Pydantic DTOs
│   │   ├── services/             # search pipeline orchestration
│   │   ├── api/                  # FastAPI routers, deps, SSE, errors
│   │   ├── workers/              # Arq tasks
│   │   └── db/                   # session, migrations (alembic/)
│   ├── tests/
│   └── pyproject.toml
├── frontend/                     # Next.js (app/, components/, lib/, hooks/, api-client/)
├── infra/                        # docker-compose.yml, Caddyfile, .env.example, backups
├── docs/architecture/            # this document
└── .github/workflows/            # CI/CD
```

## 20. Security Considerations

Single-tenant does not mean lax; domain-specific concerns dominate.

- **Secrets:** source + LLM keys from env / Docker secrets / (later) Vault; never in VCS; encrypted-at-rest if stored. Operator-key model keeps Phase 1 simple.
- **SSRF (high priority):** URL/domain sources — and future report-fetch — must **reject private, loopback, link-local, and cloud-metadata ranges**; allowlist schemes; resolve-then-validate (defeats DNS rebinding); restrict egress.
- **Prompt injection (high priority):** all source/report text treated as untrusted data, delimited/labeled; model forbidden from acting on embedded instructions; no side-effecting AI tools in Phase 1; structured outputs constrain responses (§15).
- **Handling malicious artifacts safely:** never auto-execute/auto-open samples or URLs; defang on display; safe-download patterns only.
- **Input validation & abuse:** strict Pydantic validation; size limits on bulk; per-token rate limiting; query-depth limits.
- **AuthZ/AuthN:** session auth for UI + bearer tokens for API; minimal RBAC in single-tenant; **OIDC/SSO is a documented seam** for SaaS/enterprise.
- **Audit:** append-only `audit_log` / `search_queries` of searches and admin actions.
- **Supply chain:** pinned deps, `pip-audit`/Dependabot/Renovate, SBOM, Trivy image scans, non-root containers, read-only rootfs where possible.
- **Transport & data:** TLS at Caddy; HSTS; secure cookies; retention bounded by source ToS.

## 21. Performance Considerations

- **Async on the whole source path;** `asyncio.gather` federation with strict per-source timeouts.
- **Latency targets:** classification < 50 ms; cached result < 200 ms; fresh federated search 2–10 s **streamed** (first source items < 1 s); AI synthesis streamed after results gather.
- **Cache-first** (§16) — the dominant optimization.
- **DB:** unique/btree on `(type, value)` and `type`; GIN on JSONB `normalized`; `pg_trgm` for reference/history; async pool sized to workload; `EXPLAIN`-driven tuning only when needed.
- **Concurrency control:** single-flight per `(source, value)`; bounded fan-out; Arq for slow/bulk so the request path stays snappy.
- **AI latency/cost:** prompt caching warms the static prefix; model routing keeps triage on Haiku; streaming for long Opus syntheses; Batch API for non-interactive bulk.
- **Frontend:** SSE progressive rendering, TanStack Query caching, code-splitting, defer graph libs until that feature ships.

## 22. Testing Strategy

- **Entity classification (highest-value unit tests):** a large **table of `query → expected entity type(s) + confidence`**, covering all entity types, defanged, ambiguous, and adversarial inputs (e.g., `1.2.3.4` vs version string, 32-hex MD5 vs GUID, `emotet` vs a domain). Pure, fast, deterministic.
- **Source routing:** unit tests over the entity-type → source matrix.
- **Sources:** **contract tests against recorded fixtures** (`respx`/VCR) — never hit live APIs in CI; explicit timeout/rate-limit/error/not-found paths.
- **Normalization & ranking:** golden tests for raw→`SearchResultItem`; ranking tests asserting deterministic, explainable ordering across mixed source kinds.
- **Scoring:** unit tests over evidence permutations incl. disagreement, staleness, "insufficient data"; calibration eval set.
- **AI plumbing vs quality (separate):** plumbing tests mock the LLM and assert structured-output **schema validity**, grounding (no uncited claim), and injection resistance (malicious fixture text must not alter behavior). **Quality** is an offline **eval harness** with curated queries + rubric scoring — not a CI pass/fail gate.
- **API:** contract tests + **Schemathesis** fuzzing against the OpenAPI schema.
- **Security:** SSRF range tests, prompt-injection corpus, authz tests.
- **Frontend:** Vitest (units), Playwright (E2E: search → streamed results → entity result).
- **Tooling:** `pytest` + `pytest-asyncio`; coverage gate on the deterministic core (classifier/router/scoring/normalize/ranker).

## 23. CI/CD Recommendations

GitHub Actions:

- **PR pipeline:** `ruff format --check` + `ruff check`; `mypy`/`pyright`; `pytest` + coverage (gate the deterministic core); frontend `eslint` + `tsc --noEmit` + `vitest`; OpenAPI schema-diff (frontend client must regenerate).
- **Security:** `pip-audit`, `npm audit`, **Trivy** image scan, secret scanning, SBOM.
- **Build & publish:** multi-stage Docker builds for `api`, `worker`, `frontend`; push to **GHCR** on tag/main.
- **Deploy (self-host friendly):** publish versioned images + a `docker-compose.yml`; host pulls (manual / Watchtower / Ansible). Migrations gated (`alembic upgrade head`).
- **Hygiene:** pre-commit hooks mirroring CI; branch protection; **Renovate/Dependabot**; conventional commits + changelog.

## 24. Deployment Architecture

**Single-node Docker Compose** for self-hosting — the lean target.

```
                 ┌─────────── Caddy (TLS, reverse proxy) ───────────┐
                 │                                                   │
            frontend (Next.js)                              api (FastAPI/uvicorn)
                                                              │        │
                                                   worker (Arq)        │
                                                              │        │
                                                  ┌───────────┴────┐   │
                                              Redis (cache/queue) Postgres (durable)
```

- **Services:** `caddy`, `frontend`, `api`, `worker`, `postgres`, `redis` — one `docker-compose.yml`, `.env` for config/secrets, named volumes, healthchecks.
- **Ops:** automated `pg_dump` backups + restore runbook; Prometheus scrape + optional Grafana; centralized structured logs; `/health` and `/ready`.
- **Self-host ergonomics:** prebuilt GHCR images + a single compose file = `docker compose up`. A distribution advantage for the lean/self-hosted audience.
- **Path to SaaS (documented, not built):** same images run on Kubernetes/Helm; extract the **Search Orchestrator** and **AI synthesis** as the first horizontally-scaled services; add multi-tenancy (tenant_id scoping + per-tenant key vaults) at the `services`/`models` seam.

## 25. Future Roadmap

The Search-first architecture *enables* these without redesign; it does not build them now.

- **Phase 2 — Reports & Knowledge as Sources:** Threat Report Parser + IOC extraction feed a **report search source** (injection-hardened ingestion, §15); the **internal Knowledge Base** becomes another search source (Postgres + pgvector for semantic recall). Relationship Graph renders the STIX SROs search already produces (Cytoscape/React Flow). Malware-family & threat-actor correlation matures.
- **Phase 3 — YARA Generator (next major phase):** a `DetectionGenerator` plugin that **consumes** the enriched entity model search yields (entity + behaviors + MITRE + sample features); validated by `yara-python`; AI-assisted explanation.
- **Phase 4 — Sigma & broader detection:** Sigma generator, detection-rule generator, threat-hunting queries, SIEM query generation — all `DetectionGenerator`/`Exporter` plugins.
- **Phase 5 — Enterprise:** multi-tenancy, SSO/OIDC, RBAC, collaboration/case management, audit/compliance (SOC 2), on-prem packaging.

## 26. Phase Breakdown

**Phase 1 — Universal Search Engine (now):**
1. Scaffold (monorepo, Docker Compose, CI, telemetry, settings).
2. `search/` core — query understanding + **universal entity classifier** (all entity types) + ambiguity/confidence + the big classification test table; source router.
3. `sources/` — `SearchSource` interface, registry/routing, normalizers; **external TI** sources (VT, AbuseIPDB, URLhaus, OTX, MalwareBazaar, OpenPhish, PhishTank) and **reference** sources (MITRE, CVE/NVD, malware/actor knowledge) with timeouts/circuit-breakers/rate-limits.
4. `scoring/` — transparent, versioned, evidence-weighted IOC band; `enrichment/` IOC capability composing IOC sources + scoring.
5. Aggregation/correlation/**ranking** across source kinds; cross-entity relationships.
6. `ai/` — Claude abstraction, versioned prompts, structured-output schemas, model router, grounding/injection guards, synthesis cache (Haiku triage + Opus cross-source correlation + MITRE mapping).
7. Caching (Redis L1 + Postgres L2 + AI L3), single-flight, refresh.
8. `api/` + SSE streaming; `services/` search-pipeline orchestration; bulk via Arq.
9. Frontend: universal search box → streamed per-source results → entity-aware result rendering (IOC band+evidence; technique/CVE/family/actor profiles) → AI synthesis with citations → cross-entity pivot; history; source health; export.
10. Security pass (SSRF, injection, secrets, audit), tests, docs, release images.

**Definition of done for Phase 1:** search almost anything → correct entity type(s) (with confidence + override for ambiguous/soft) → routed, streamed, federated results across TI + reference sources → for IOC entities a transparent evidence-based band (never bare "malicious"); for other entities a knowledge profile → grounded, cited AI synthesis with MITRE mapping and cross-entity correlation → persisted, permalinkable, exportable, pivotable result.

Later phases per §25 — **reports and the KB land as new search sources**, detection generators as consumers — with no change to the search core.

---

## 27. Critical Self-Review (challenging my own architecture)

A Principal Architect should attack the proposal before approving it. Where this Search-first design is weakest:

1. **Over-abstraction is the defining risk of this reframe.** "Everything is search" is elegant but can produce a beautiful orchestration layer that does nothing concretely well. The discipline that prevents this: Phase 1 must ship **fully real IOC + reference search** — actual VT/AbuseIPDB/OTX/MITRE/CVE integrations, real scoring, real AI synthesis — *using* the abstractions, not just defining them. An abstraction earns its place only when ≥2 concrete sources exercise it. If forced to choose, ship fewer sources fully over more sources as stubs.

2. **Cross-source ranking/relevance is genuinely hard and I have under-specified it.** A VT reputation, a MITRE technique, and a report snippet aren't comparable on one axis. My answer — normalize per source kind, group results *per entity*, rank by `reliability × relevance × recency`, and never present one flat list — is directionally right but needs an eval set and iteration. Honest stance: in Phase 1, prefer **clear per-source, per-entity grouping** over a clever unified relevance score; introduce global ranking only once there's data to calibrate it. A confident-but-wrong ranking is worse than transparent grouping.

3. **The "AI never detects" rule is violated in spirit by soft entity types, and the design must say so plainly.** Malware family, threat actor, process, API, PowerShell, and file name can't be detected deterministically; they need maintained reference data (actor aliases, LOLBAS, malpedia) that goes stale. Mitigation: scope Phase 1's *reliable* auto-classification to structured entities; treat soft types as best-effort with explicit low confidence and mandatory user confirmation; seed reference data from public sources. Do **not** quietly let the LLM classify to hide the gap — that reintroduces the hallucination risk the whole design exists to avoid.

4. **Source rate limits may make interactive federated search frustrating regardless of architecture, and federation makes it worse** (one query touches several sources at once). Caching helps repeat queries but cannot manufacture quota for novel ones. Mitigation: budget meters in the UI, multi-key pooling, per-type source prioritization, premium-key path, and streamed partial results so a throttled source degrades gracefully. This is partly a business/licensing problem, not solvable by code.

5. **Prompt injection is amplified by the search core.** More sources = more attacker-controlled text reaching the synthesis prompt (and, in Phase 2, whole uploaded reports). Structured outputs + delimiting + "no tools" is the right posture but must be adversarially tested (injection corpus in CI) and revisited the moment AI gains any tool capability. Under-rating this is the most likely way the product embarrasses itself.

6. **Source ToS/licensing could block the very federation that creates value** (caching duration, redistribution, future SaaS resale). The per-source policy registry helps, but this needs **legal review before SaaS**; the single-tenant operator-key model is partly chosen because it sidesteps redistribution. Be explicit that SaaS is gated on licensing, not just engineering.

7. **Risk of building too much, made larger by a "universal" framing.** pgvector, OTel, the plugin generality, STIX alignment, the report/KB source interfaces — each defensible, but together they can balloon Phase 1. Discipline: provision pgvector/OTel but don't *use* them yet; define the report/KB `SearchSource` interface but implement only TI + reference sources; STIX-*shape* the model without importing full STIX machinery. The compose-first, Postgres-first, monolith-first posture is the antidote to my own enthusiasm.

8. **Where the monolith hurts first** is the synchronous federation path mixing fast and slow sources. The fix is more aggressive backgrounding (return classification + cache instantly, stream the rest) — not microservices. The SSE-first API makes this tractable, but it means the frontend must be designed for partial/eventual results from day one — a real complexity I should not understate.

**Net:** the Search-as-core architecture is the **better** design — it matches the long-term vision, unifies the roadmap behind one extension seam, and generalizes the parts that were already strong — *provided* we (a) ship Phase 1's IOC + reference search fully and concretely rather than as a framework, (b) prefer transparent per-entity grouping over premature unified ranking, (c) tell the truth about soft-type classification limits, and (d) treat rate limits, ToS, and prompt injection as adversarial, tested, and partly-business constraints. I would approve this to proceed to Phase 1 implementation planning, with those four caveats recorded as explicit project risks.

---

## Execution & Verification (post-approval)

This is a documentation deliverable; **no application code is produced in Phase 0.**

**Execution after approval:**
1. Create `docs/architecture/` and write this specification to `docs/architecture/PHASE-0-ARCHITECTURE.md`.
2. Commit on branch `claude/magical-knuth-lih9s1` with a descriptive message.
3. Push with `git push -u origin claude/magical-knuth-lih9s1`.

**Verification:**
- Confirm the committed Markdown contains all 26 required sections plus the critical self-review, renders cleanly, and reflects both the **Search-as-core** architecture (IOC analysis as one search capability) and the three confirmed constraints (self-hosted single-tenant · lean small team · Python/FastAPI + Next.js/React).
- `git status` clean and branch pushed; the file is viewable on the remote branch.
- No source/config/dependency files are added or modified in this phase.
