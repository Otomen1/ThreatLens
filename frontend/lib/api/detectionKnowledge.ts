// Detection Knowledge Library — COMMUNITY detections.
// Kept deliberately separate from the generated DetectionPackage (./detection):
// a community rule is authored elsewhere, carries its own provenance, and is
// never merged with generated content.

import { get, post } from "./client";
import type { DetectionCategory, DetectionLanguage } from "./detection";
import type { EntityType, InvestigationSummary } from "./investigation";

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
