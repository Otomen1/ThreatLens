// Core entity detection and investigation (Threat Intelligence + reference
// knowledge, then the deterministic Reasoning Engine). Every other subsystem
// module builds on the Entity/InvestigationSummary types defined here.

import { postQuery } from "./client";

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
