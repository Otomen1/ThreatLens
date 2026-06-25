// Typed client for the ThreatLens detection API.
//
// Detection lives entirely in the backend engine; this module only transports
// the request and types the response. The base URL is configurable so the same
// build works same-origin (default) or against a separately-hosted backend.

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
 * Classify a query via the backend detection engine.
 *
 * Pass an {@link AbortSignal} to cancel an in-flight request; an abort
 * propagates as a `DOMException` named `AbortError` (re-thrown, not wrapped).
 */
export async function detect(
  query: string,
  signal?: AbortSignal,
): Promise<DetectResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/detect`, {
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

  return (await res.json()) as DetectResponse;
}
