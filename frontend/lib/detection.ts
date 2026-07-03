// Pure helpers for rendering DetectionPackage artifacts. No React, no I/O —
// unit-testable in the node test environment.

import type { DetectionArtifact, DetectionLanguage } from "./api";

const SEVERITY_LABELS = ["Informational", "Low", "Medium", "High", "Critical"] as const;

/** Human label for an ordinal detection severity (0–4). */
export function detectionSeverityLabel(severity: number): string {
  return SEVERITY_LABELS[severity] ?? "Unknown";
}

/** Tailwind classes for a severity badge (higher = hotter). */
export function detectionSeverityClass(severity: number): string {
  switch (severity) {
    case 4:
      return "text-red-300 bg-red-500/10 border-red-500/30";
    case 3:
      return "text-orange-300 bg-orange-500/10 border-orange-500/30";
    case 2:
      return "text-amber-300 bg-amber-500/10 border-amber-500/30";
    case 1:
      return "text-yellow-300 bg-yellow-500/10 border-yellow-500/30";
    default:
      return "text-zinc-400 bg-zinc-800 border-zinc-700";
  }
}

const FILE_EXTENSIONS: Record<string, string> = {
  sigma: "yml",
  yara: "yar",
  suricata: "rules",
  snort: "rules",
  splunk_spl: "spl",
  sentinel_kql: "kql",
  elastic_esql: "esql",
  chronicle_yara_l: "yaral",
  qradar_aql: "aql",
};

/** A safe download filename for an artifact (stable id, language extension). */
export function artifactFilename(artifact: DetectionArtifact): string {
  const base = (artifact.rule_id ?? artifact.id).replace(/[^a-zA-Z0-9._-]/g, "-");
  const ext = FILE_EXTENSIONS[artifact.language] ?? "txt";
  return `${base}.${ext}`;
}

// --------------------------------------------------------------------------- //
// Language-first grouping (shared display order/labels for both Detection
// Engineering and Detection Knowledge — same languages, same presentation).
// --------------------------------------------------------------------------- //

/** Canonical scan order: the nine shipped generators first, then future ones. */
export const DETECTION_LANGUAGE_ORDER: DetectionLanguage[] = [
  "sigma",
  "yara",
  "suricata",
  "snort",
  "splunk_spl",
  "sentinel_kql",
  "elastic_esql",
  "chronicle_yara_l",
  "qradar_aql",
  "elastic_eql",
  "crowdstrike",
  "trend_vision_one",
  "stellar_cyber",
  "generic",
];

const LANGUAGE_LABELS: Record<DetectionLanguage, string> = {
  sigma: "Sigma",
  yara: "YARA",
  suricata: "Suricata",
  snort: "Snort",
  splunk_spl: "Splunk SPL",
  sentinel_kql: "Sentinel KQL",
  elastic_esql: "Elastic ES|QL",
  elastic_eql: "Elastic EQL",
  chronicle_yara_l: "Chronicle YARA-L",
  qradar_aql: "QRadar AQL",
  crowdstrike: "CrowdStrike",
  trend_vision_one: "Trend Vision One",
  stellar_cyber: "Stellar Cyber",
  generic: "Generic",
};

/** Human display name for a detection language (shared by both panels). */
export function detectionLanguageLabel(language: DetectionLanguage): string {
  return LANGUAGE_LABELS[language] ?? language;
}

export interface LanguageGroup<T> {
  language: DetectionLanguage;
  label: string;
  items: T[];
}

/**
 * Group items by language in canonical scan order (only languages present are
 * returned). Item order within a group is preserved — the engine already
 * returns artifacts deterministically ordered by severity.
 */
export function groupByLanguage<T extends { language: DetectionLanguage }>(
  items: T[],
): LanguageGroup<T>[] {
  const byLanguage = new Map<DetectionLanguage, T[]>();
  for (const item of items) {
    const bucket = byLanguage.get(item.language);
    if (bucket) bucket.push(item);
    else byLanguage.set(item.language, [item]);
  }
  return DETECTION_LANGUAGE_ORDER.filter((language) => byLanguage.has(language)).map(
    (language) => ({
      language,
      label: detectionLanguageLabel(language),
      items: byLanguage.get(language)!,
    }),
  );
}

/**
 * Extract ATT&CK technique ids from an artifact's free-form metadata bag.
 * Generators record them under "attack" (Sigma/YARA/network) or "mitre" (SIEM);
 * "n/a" is Chronicle's explicit empty marker.
 */
export function mitreFromMetadata(metadata: Record<string, string>): string[] {
  const raw = metadata.attack || metadata.mitre || "";
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0 && t.toLowerCase() !== "n/a");
}

/** The canonical MITRE ATT&CK page for a technique id, e.g. "T1204.002". */
export function mitreTechniqueUrl(technique: string): string {
  const [base, sub] = technique.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}
