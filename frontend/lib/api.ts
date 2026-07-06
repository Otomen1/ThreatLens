// Typed client for the ThreatLens API.
//
// Detection and enrichment live entirely in the backend; this module only
// transports requests and types responses. The base URL is configurable so the
// same build works same-origin (default) or against a separately-hosted backend.

export type EntityType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "email"
  | "md5"
  | "sha1"
  | "sha256"
  | "cve"
  | "cwe"
  | "capec"
  | "mitre_technique"
  | "registry_key"
  | "process_name"
  | "powershell_command"
  | "windows_api"
  | "file_name"
  | "threat_actor"
  | "malware_family"
  | "freetext"
  | "unknown";

export type ValidationStatus = "valid" | "invalid" | "unvalidated";

export interface EntityMatch {
  type: EntityType;
  confidence: number;
}

export interface RoutingMetadata {
  providers: string[];
}

export interface Entity {
  type: EntityType;
  value: string;
  normalized_value: string;
  confidence: number;
  validation: ValidationStatus;
  possible_matches: EntityMatch[];
  routing: RoutingMetadata;
}

export interface DetectResponse {
  search_id: string;
  entity: Entity;
}

// --- intelligence (provider results) ---

export type ResultStatus =
  | "ok"
  | "not_found"
  | "unsupported"
  | "partial"
  | "error"
  | "timeout"
  | "rate_limited"
  | "unauthorized";

export type ReputationLevel =
  | "unknown"
  | "benign"
  | "likely_benign"
  | "suspicious"
  | "likely_malicious"
  | "malicious";

export interface Reputation {
  level: ReputationLevel;
  score: number | null;
  malicious_count: number | null;
  total_count: number | null;
  summary: string | null;
}

export interface Evidence {
  type: string;
  summary: string;
  value: string | null;
  confidence: number | null;
  observed_at: string | null;
  data: Record<string, unknown>;
}

export interface Relationship {
  relationship: string;
  target_type: string;
  target_value: string;
  confidence: number | null;
  description: string | null;
}

export interface Reference {
  title: string;
  url: string;
  description: string | null;
}

export interface ResultError {
  message: string;
  retryable: boolean;
  detail: string | null;
}

// Aggregated across all providers; the client never sees per-provider payloads.

export interface ProviderSummary {
  provider: string;
  provider_display_name: string | null;
  status: ResultStatus;
  reputation: Reputation | null;
  error: ResultError | null;
}

export interface AttributedEvidence {
  evidence: Evidence;
  sources: string[];
}

export interface AttributedRelationship {
  relationship: Relationship;
  sources: string[];
}

export interface AttributedReference {
  reference: Reference;
  sources: string[];
}

export interface AggregatedResult {
  entity_type: EntityType;
  entity_value: string;
  providers: ProviderSummary[];
  evidence: AttributedEvidence[];
  relationships: AttributedRelationship[];
  references: AttributedReference[];
  tags: string[];
  metadata: Record<string, unknown>;
}

// --- reasoning (Investigation Intelligence Engine) ---
//
// The deterministic engine's output. The UI is a pure consumer: it never
// recalculates severity, confidence, or priority — every value shown is taken
// verbatim from these models. Severity and posture are ordinal integers (0–4).

export type ConfidenceBand = "insufficient" | "low" | "moderate" | "high" | "very_high";

export interface ConfidenceFactor {
  name: string;
  contribution: number;
  detail: string;
}

export interface Confidence {
  score: number;
  band: ConfidenceBand;
  contested: boolean;
  factors: ConfidenceFactor[];
}

export type EvidencePolarity = "supporting" | "contradicting" | "contextual";

export interface WeightedEvidence {
  evidence: AttributedEvidence;
  weight: number;
  polarity: EvidencePolarity;
  dimension: string;
}

export type RecommendationCategory =
  | "containment"
  | "investigation"
  | "remediation"
  | "forensics";

export interface Recommendation {
  action: string;
  category: RecommendationCategory;
  priority: number;
  target_type: EntityType;
  target_value: string;
  rationale: string;
  rule_id: string;
  finding_ids: string[];
}

export interface Finding {
  id: string;
  title: string;
  categories: string[];
  subject_type: EntityType;
  subject_value: string;
  severity: number;
  confidence: Confidence;
  priority: number;
  evidence: WeightedEvidence[];
  relationships: AttributedRelationship[];
  sources: string[];
  rationale: string;
  rule_ids: string[];
  recommendations: Recommendation[];
}

export interface InvestigationSummary {
  entity_type: EntityType;
  entity_value: string;
  posture: number;
  overall_confidence: Confidence;
  categories: string[];
  findings: Finding[];
  recommendations: Recommendation[];
  engine_version: string;
  generated_at: string;
}

export interface InvestigationResponse {
  investigation_id: string;
  entity: Entity;
  threat_intelligence: AggregatedResult;
  knowledge: AggregatedResult;
  investigation_summary: InvestigationSummary;
}

// --- AI explanation (downstream, optional) ---
//
// The AI layer explains a completed InvestigationSummary. It never influences
// findings, confidence, severity, priority, or recommendations. A non-"ok"
// status (disabled / unavailable / error) is a normal, expected response — not a
// failure — and the deterministic investigation always renders regardless.

export type AIStatus =
  | "ok"
  | "disabled"
  | "unavailable"
  | "timeout"
  | "invalid_response"
  | "error";

export interface FindingExplanation {
  finding_id: string;
  explanation: string;
}

export interface RecommendationExplanation {
  action: string;
  target_value: string;
  explanation: string;
}

export interface AIExplanation {
  status: AIStatus;
  provider: string;
  model: string | null;
  message: string;
  executive_summary: string;
  technical_summary: string;
  finding_explanations: FindingExplanation[];
  recommendation_explanations: RecommendationExplanation[];
  limitations: string[];
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api/v1";

/** Error raised for any non-success API response or unreachable backend. */
export class ApiError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/**
 * POST `{ query }` to an API path and return the parsed JSON.
 *
 * Pass an {@link AbortSignal} to cancel an in-flight request; an abort
 * propagates as a `DOMException` named `AbortError` (re-thrown, not wrapped).
 */
async function post<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the service.");
  }

  if (!res.ok) {
    let message = `Request failed (${res.status}).`;
    if (res.status === 422) message = "That request could not be processed.";
    throw new ApiError(message, res.status);
  }

  return (await res.json()) as T;
}

/** POST `{ query }` to an API path and return the parsed JSON. */
function postQuery<T>(path: string, query: string, signal?: AbortSignal): Promise<T> {
  return post<T>(path, { query }, signal);
}

/** GET an API path and return the parsed JSON (used by read-only health checks). */
async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { method: "GET", signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the service.");
  }
  if (!res.ok) throw new ApiError(`Request failed (${res.status}).`, res.status);
  return (await res.json()) as T;
}

/** Classify a query into a normalized entity (detection only). */
export function detect(query: string, signal?: AbortSignal): Promise<DetectResponse> {
  return postQuery<DetectResponse>("/detect", query, signal);
}

/** Detect an entity and run TI + reference providers concurrently. */
export function investigate(
  query: string,
  signal?: AbortSignal,
): Promise<InvestigationResponse> {
  return postQuery<InvestigationResponse>("/investigate", query, signal);
}

/**
 * Ask the AI layer to explain a completed investigation.
 *
 * Sends the deterministic {@link InvestigationSummary} (never raw provider data)
 * and returns an {@link AIExplanation}. The endpoint always responds 200; a
 * `disabled` / `unavailable` / `error` status is a normal result the caller
 * renders as a friendly note, not an exception.
 */
export function explain(
  summary: InvestigationSummary,
  signal?: AbortSignal,
): Promise<AIExplanation> {
  return post<AIExplanation>("/explain", summary, signal);
}

// --- operational health (read-only) ---
//
// Lightweight, side-effect-free status endpoints. They never run an
// investigation or consume provider quota; the frontend uses them only to show
// a passive system-status indicator.

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  uptime_seconds: number;
  started_at: string;
  timestamp: string;
}

export type AIHealthStatus = "disabled" | "ok" | "unavailable" | "error";

export interface AIHealth {
  status: AIHealthStatus;
  enabled: boolean;
  provider: string;
  model: string | null;
  reachable: boolean;
  model_available: boolean | null;
  detail: string | null;
  timestamp: string;
}

/** Liveness probe — resolves when the backend is up. */
export function health(signal?: AbortSignal): Promise<HealthStatus> {
  return get<HealthStatus>("/health", signal);
}

/** AI subsystem status (disabled / reachable / unavailable). */
export function aiHealth(signal?: AbortSignal): Promise<AIHealth> {
  return get<AIHealth>("/health/ai", signal);
}

// --- detection engineering (downstream, optional) ---
//
// The Detection Engine is a pure, deterministic consumer of a completed
// InvestigationSummary. It converts findings into reusable detection content and
// never influences findings, confidence, severity, priority, recommendations, or
// relationships. In this phase no generators are registered, so the package is
// well-formed but carries no artifacts (`artifacts: []`).

export type DetectionLanguage =
  | "sigma"
  | "yara"
  | "suricata"
  | "snort"
  | "splunk_spl"
  | "sentinel_kql"
  | "elastic_eql"
  | "elastic_esql"
  | "chronicle_yara_l"
  | "qradar_aql"
  | "crowdstrike"
  | "trend_vision_one"
  | "stellar_cyber"
  | "generic";

export type DetectionCategory =
  | "network"
  | "host"
  | "file"
  | "process"
  | "registry"
  | "dns"
  | "http"
  | "email"
  | "identity"
  | "cloud"
  | "vulnerability"
  | "behavioral"
  | "generic";

export type DetectionValidationStatus =
  | "unvalidated"
  | "valid"
  | "invalid"
  | "unsupported"
  | "skipped";

export interface DetectionReference {
  title: string;
  url: string | null;
  description: string | null;
}

export interface DetectionTarget {
  language: DetectionLanguage;
  platform: string;
  product: string | null;
}

export interface DetectionValidation {
  status: DetectionValidationStatus;
  validator: string | null;
  messages: string[];
}

// Severity is an ordinal integer (0–4) copied from the finding — never recomputed.
export interface DetectionArtifact {
  id: string;
  language: DetectionLanguage;
  target: DetectionTarget;
  title: string;
  description: string;
  content: string;
  severity: number;
  category: DetectionCategory;
  capabilities: string[];
  source_finding_ids: string[];
  references: DetectionReference[];
  validation: DetectionValidation;
  rule_id: string | null;
  metadata: Record<string, string>;
}

export interface DetectionMetadata {
  engine_version: string;
  source_engine_version: string;
  entity_type: EntityType;
  entity_value: string;
  generated_at: string;
  source_finding_count: number;
  source_posture: number;
}

export interface DetectionPackage {
  id: string;
  metadata: DetectionMetadata;
  artifacts: DetectionArtifact[];
  languages: DetectionLanguage[];
  references: DetectionReference[];
  source_finding_ids: string[];
}

/**
 * Generate a {@link DetectionPackage} from a completed investigation.
 *
 * Sends the deterministic {@link InvestigationSummary} and returns the package.
 * The endpoint is a pure consumer — it never changes the investigation — and in
 * this phase returns an empty (artifact-free) package.
 */
export function generateDetections(
  summary: InvestigationSummary,
  signal?: AbortSignal,
): Promise<DetectionPackage> {
  return post<DetectionPackage>("/detections", summary, signal);
}

// --------------------------------------------------------------------------- //
// Detection Knowledge Library (Phase 4.6) — COMMUNITY detections.
// Kept deliberately separate from the generated DetectionPackage above: a
// community rule is authored elsewhere, carries its own provenance, and is never
// merged with generated content.
// --------------------------------------------------------------------------- //

export type RuleMatchType = "exact" | "partial" | "related" | "none";
export type LicenseSupport =
  | "permissive"
  | "copyleft"
  | "restricted"
  | "unsupported"
  | "unknown";
export type SyncStatus = "seed" | "synced" | "stale" | "error";

export interface RuleLicense {
  spdx_id: string;
  name: string;
  support: LicenseSupport;
  url: string | null;
  note: string;
}

export interface RuleAuthor {
  name: string;
  url: string | null;
  organization: string | null;
}

export interface RuleReference {
  title: string;
  url: string;
}

export interface RuleVersion {
  version: string;
  revision: number;
  content_hash: string;
  updated: string | null;
}

export interface RuleSource {
  id: string;
  name: string;
  repository: string;
  url: string;
  license: RuleLicense;
  priority: number;
  languages: DetectionLanguage[];
  description: string;
}

export interface RuleIOC {
  type: EntityType;
  value: string;
}

export interface CommunityRule {
  id: string;
  source: RuleSource;
  rule_id: string;
  name: string;
  language: DetectionLanguage;
  category: DetectionCategory;
  severity: number;
  description: string;
  author: RuleAuthor;
  license: RuleLicense;
  version: RuleVersion;
  url: string;
  path: string;
  tags: string[];
  mitre_techniques: string[];
  threat_actors: string[];
  malware_families: string[];
  platforms: string[];
  iocs: RuleIOC[];
  references: RuleReference[];
  content: string | null;
}

export interface RuleMatch {
  rule: CommunityRule;
  match_type: RuleMatchType;
  similarity: number;
  coverage: number;
  shared_iocs: string[];
  shared_techniques: string[];
  shared_malware: string[];
  shared_actors: string[];
  rationale: string;
}

export interface CommunityRecommendation {
  entity_type: EntityType;
  entity_value: string;
  matches: RuleMatch[];
  exact_count: number;
  partial_count: number;
  related_count: number;
  library_version: string;
  sync_status: SyncStatus;
  generated_at: string | null;
}

export interface LibraryStats {
  total_rules: number;
  sources: number;
  sync_status: SyncStatus;
  by_language: Record<string, number>;
  by_source: Record<string, number>;
  library_version: string;
}

export interface CommunitySearchResult {
  total: number;
  rules: CommunityRule[];
  stats: LibraryStats;
}

/**
 * Recommend COMMUNITY detections resembling a completed investigation.
 *
 * Downstream, read-only, deterministic (no AI, no embeddings, no network): the
 * same summary always yields the same ranked matches. These complement — never
 * replace or merge with — the generated {@link DetectionPackage}.
 */
export function recommendCommunityDetections(
  summary: InvestigationSummary,
  signal?: AbortSignal,
): Promise<CommunityRecommendation> {
  return post<CommunityRecommendation>("/detection-knowledge/recommend", summary, signal);
}

/** Search the offline community library by any combination of axes. */
export function searchCommunityDetections(
  params: Record<string, string | number | undefined>,
  signal?: AbortSignal,
): Promise<CommunitySearchResult> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const suffix = query.toString();
  return get<CommunitySearchResult>(
    `/detection-knowledge/search${suffix ? `?${suffix}` : ""}`,
    signal,
  );
}

// --- operational dashboard (read-only) ---
//
// Administrators/developers only — never rendered inside the Investigation
// Workspace. Every endpoint is GET and side-effect-free: no request here can
// trigger an investigation, a detection generation, or an AI call.

export type ServiceState = "healthy" | "degraded" | "offline" | "disabled";

export interface ServiceStatus {
  name: string;
  display_name: string;
  status: ServiceState;
  detail: string;
}

export interface SystemHealthResponse {
  status: ServiceState;
  services: ServiceStatus[];
  timestamp: string;
}

export interface ProviderUsage {
  name: string;
  display_name: string;
  configured: boolean;
  enabled: boolean;
  requests: number;
  successful: number;
  failed: number;
  success_rate: number | null;
  avg_latency_ms: number | null;
  last_request_at: string | null;
  rate_limit_remaining: number | null;
  cache_hits: number;
  cache_misses: number;
}

export interface KnowledgeProviderUsage {
  name: string;
  display_name: string;
  queries: number;
  successful: number;
  failed: number;
  avg_latency_ms: number | null;
  cache_hits: number;
  cache_misses: number;
}

export interface AIUsage {
  provider: string;
  model: string | null;
  enabled: boolean;
  connected: boolean;
  requests: number;
  successful: number;
  failed: number;
  avg_response_ms: number | null;
  fastest_response_ms: number | null;
  slowest_response_ms: number | null;
  avg_prompt_chars: number | null;
  avg_completion_chars: number | null;
  estimated_tokens: number | null;
  estimated_cost_usd: number | null;
}

export interface DetectionEngineeringUsage {
  generated_total: number;
  by_language: Record<string, number>;
  avg_generation_ms: number | null;
  last_generated_at: string | null;
}

export interface DetectionKnowledgeUsage {
  library_version: string;
  rules_indexed: number;
  repositories: number;
  sync_status: string;
  last_synchronized_at: string | null;
  cache_size_bytes: number | null;
  queries: number;
  avg_query_latency_ms: number | null;
}

export interface InvestigationUsage {
  executed: number;
  avg_duration_ms: number | null;
  avg_findings: number | null;
  avg_recommendations: number | null;
  avg_confidence: number | null;
  avg_ai_response_ms: number | null;
}

export interface UsageResponse {
  threat_intelligence: ProviderUsage[];
  knowledge: KnowledgeProviderUsage[];
  ai: AIUsage;
  detection_engineering: DetectionEngineeringUsage;
  detection_knowledge: DetectionKnowledgeUsage;
  investigations: InvestigationUsage;
  timestamp: string;
}

export interface ConfigItem {
  name: string;
  display_name: string;
  configured: boolean;
  enabled: boolean;
}

export interface AIConfigStatus {
  provider: string;
  enabled: boolean;
  model: string | null;
}

export interface ConfigStatusResponse {
  threat_intelligence: ConfigItem[];
  knowledge: ConfigItem[];
  ai: AIConfigStatus;
  timestamp: string;
}

/** Section 1 — per-service Healthy/Degraded/Offline/Disabled + an overall rollup. */
export function systemHealth(signal?: AbortSignal): Promise<SystemHealthResponse> {
  return get<SystemHealthResponse>("/system/health", signal);
}

/** Section 2 — incremental request/latency counters. Never includes a secret. */
export function systemUsage(signal?: AbortSignal): Promise<UsageResponse> {
  return get<UsageResponse>("/system/usage", signal);
}

/** Section 3 — configured/enabled booleans only. Never includes a credential. */
export function systemConfig(signal?: AbortSignal): Promise<ConfigStatusResponse> {
  return get<ConfigStatusResponse>("/system/config", signal);
}

// --- exposure intelligence (Phase 5.1 — Shodan is the first provider) ---
//
// Answers "where is this entity exposed", never "is it malicious" (that
// remains Threat Intelligence's question — a separate framework). Not
// integrated into /investigate: a dedicated, isolated lookup.

export type ExposureProviderHealthStatus =
  | "unknown"
  | "operational"
  | "degraded"
  | "unavailable"
  | "disabled";

export interface ExposureProviderStatusInfo {
  name: string;
  display_name: string;
  status: ExposureProviderHealthStatus;
  detail: string | null;
}

export type ExposureResultStatus =
  | "ok"
  | "not_found"
  | "unsupported"
  | "error"
  | "timeout"
  | "rate_limited"
  | "unauthorized";

export type ExposureCapability =
  | "open_ports"
  | "certificates"
  | "passive_dns"
  | "hosting"
  | "asn"
  | "services"
  | "subdomains"
  | "dns_history"
  | "breaches"
  | "credential_exposure"
  | "pastes"
  | "internet_noise";

export interface ExposureFindingErrorInfo {
  message: string;
  retryable: boolean;
  detail: string | null;
}

export interface ExposureEvidence {
  type: string;
  summary: string;
  value: string | null;
  observed_at: string | null;
  data: Record<string, unknown>;
}

export interface ExposureAsset {
  asset_type: string;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  attributes: Record<string, unknown>;
}

export interface ExposureReference {
  title: string;
  url: string;
  description: string | null;
}

export interface ExposureFinding {
  provider: string;
  provider_display_name: string | null;
  entity_type: EntityType;
  entity_value: string;
  status: ExposureResultStatus;
  error: ExposureFindingErrorInfo | null;
  category: ExposureCapability | null;
  summary: string;
  evidence: ExposureEvidence[];
  assets: ExposureAsset[];
  references: ExposureReference[];
  fetched_at: string | null;
}

export interface ExposureStatistics {
  providers_queried: number;
  providers_ok: number;
  total_findings: number;
  total_assets: number;
  categories: ExposureCapability[];
}

export interface ExposureMetadata {
  entity_type: EntityType;
  entity_value: string;
  generated_at: string;
  framework_version: string;
}

export interface ExposureSummary {
  entity_type: EntityType;
  entity_value: string;
  findings: ExposureFinding[];
  references: ExposureReference[];
  statistics: ExposureStatistics;
  metadata: ExposureMetadata;
}

export interface ExposureFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  providers_registered: number;
  providers: ExposureProviderStatusInfo[];
  summary: ExposureSummary | null;
}

/**
 * Fetch Exposure Intelligence Framework + provider status, optionally running
 * a real lookup when `value` is given (e.g. an IP). A disabled or
 * unconfigured provider still returns 200 with a well-formed empty/failed
 * summary — never an error.
 */
export function exposureFrameworkStatus(
  value?: string,
  signal?: AbortSignal,
): Promise<ExposureFrameworkStatus> {
  const trimmed = value?.trim();
  const query = trimmed ? `?value=${encodeURIComponent(trimmed)}` : "";
  return get<ExposureFrameworkStatus>(`/exposure${query}`, signal);
}

// --- identity intelligence (Phase 6.0 — framework only, no providers yet) ---
//
// Answers "what is known about this identity" (breaches, credential exposure,
// directory profile, …), never "is it malicious" or "where is it exposed"
// (those remain Threat and Exposure Intelligence's questions — separate
// frameworks). This is a pure readiness probe: no entity lookup, not
// integrated into /investigate.

export interface IdentityFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  providers_registered: number;
}

/** Fetch Identity Intelligence Framework readiness (Phase 6.0 — no providers yet). */
export function identityFrameworkStatus(signal?: AbortSignal): Promise<IdentityFrameworkStatus> {
  return get<IdentityFrameworkStatus>("/identity", signal);
}

// --- investigation correlation (Phase 7.0 — framework only) ---
//
// A pure, deterministic engine that combines a completed investigation's
// existing findings into higher-level correlation observations. It never
// invents evidence and never scores. This is a pure readiness probe: no
// correlation is run, not integrated into /investigate yet.

export interface CorrelationFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  rules_registered: number;
}

/** Fetch Investigation Correlation Engine readiness (Phase 7.0 — seed rules only). */
export function correlationFrameworkStatus(
  signal?: AbortSignal,
): Promise<CorrelationFrameworkStatus> {
  return get<CorrelationFrameworkStatus>("/correlation", signal);
}
