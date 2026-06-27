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

export interface InvestigationResponse {
  investigation_id: string;
  entity: Entity;
  threat_intelligence: AggregatedResult;
  knowledge: AggregatedResult;
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
async function postQuery<T>(
  path: string,
  query: string,
  signal?: AbortSignal,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the detection service.");
  }

  if (!res.ok) {
    let message = `Request failed (${res.status}).`;
    if (res.status === 422) message = "That query could not be processed.";
    throw new ApiError(message, res.status);
  }

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
