// Pure helpers for rendering the Detection Knowledge Library (community rules).
// No React, no I/O — unit-testable in the node test environment. Kept separate
// from lib/detection.ts because community detections are a distinct concept.

import type { CommunityRule, LicenseSupport, RuleMatchType } from "./api";

/** Human label for a match strength. */
export function matchTypeLabel(type: RuleMatchType): string {
  switch (type) {
    case "exact":
      return "Exact match";
    case "partial":
      return "Partial match";
    case "related":
      return "Related";
    default:
      return "No match";
  }
}

/** Tailwind classes for a match-type badge (exact = hottest). */
export function matchTypeClass(type: RuleMatchType): string {
  switch (type) {
    case "exact":
      return "text-emerald-300 bg-emerald-500/10 border-emerald-500/30";
    case "partial":
      return "text-sky-300 bg-sky-500/10 border-sky-500/30";
    case "related":
      return "text-zinc-300 bg-zinc-500/10 border-zinc-500/30";
    default:
      return "text-zinc-400 bg-zinc-800 border-zinc-700";
  }
}

/** Deterministic sort rank for grouping matches (exact first). */
export function matchTypeOrder(type: RuleMatchType): number {
  return { exact: 0, partial: 1, related: 2, none: 3 }[type] ?? 4;
}

/** Colour class for a 0–100 similarity score. */
export function similarityClass(score: number): string {
  if (score >= 70) return "text-emerald-300";
  if (score >= 40) return "text-sky-300";
  if (score >= 15) return "text-amber-300";
  return "text-zinc-400";
}

/** Human label for a license's redistribution posture. */
export function licenseSupportLabel(support: LicenseSupport): string {
  switch (support) {
    case "permissive":
      return "Permissive";
    case "copyleft":
      return "Copyleft";
    case "restricted":
      return "Restricted";
    case "unsupported":
      return "Unsupported";
    default:
      return "Unknown";
  }
}

/** Whether a rule's content may be shown/downloaded under its license. */
export function isRedistributable(support: LicenseSupport): boolean {
  return support === "permissive" || support === "copyleft";
}

const FILE_EXTENSIONS: Record<string, string> = {
  sigma: "yml",
  yara: "yar",
  suricata: "rules",
  snort: "rules",
  splunk_spl: "spl",
  sentinel_kql: "kql",
  elastic_esql: "esql",
  elastic_eql: "eql",
  chronicle_yara_l: "yaral",
  qradar_aql: "aql",
};

/** A safe download filename for a community rule (stable id + language ext). */
export function communityRuleFilename(rule: CommunityRule): string {
  const base = (rule.rule_id || rule.id).replace(/[^a-zA-Z0-9._-]/g, "-");
  const ext = FILE_EXTENSIONS[rule.language] ?? "txt";
  return `${base}.${ext}`;
}
