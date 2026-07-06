// Detection Engineering (downstream, optional).
//
// The Detection Engine is a pure, deterministic consumer of a completed
// InvestigationSummary. It converts findings into reusable detection content and
// never influences findings, confidence, severity, priority, recommendations, or
// relationships.

import { post } from "./client";
import type { EntityType, InvestigationSummary } from "./investigation";

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
 * The endpoint is a pure consumer — it never changes the investigation.
 */
export function generateDetections(
  summary: InvestigationSummary,
  signal?: AbortSignal,
): Promise<DetectionPackage> {
  return post<DetectionPackage>("/detections", summary, signal);
}
