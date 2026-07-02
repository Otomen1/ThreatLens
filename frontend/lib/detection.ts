// Pure helpers for rendering DetectionPackage artifacts. No React, no I/O —
// unit-testable in the node test environment.

import type { DetectionArtifact } from "./api";

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

const FILE_EXTENSIONS: Record<string, string> = { sigma: "yml", yara: "yar" };

/** A safe download filename for an artifact (stable id, language extension). */
export function artifactFilename(artifact: DetectionArtifact): string {
  const base = (artifact.rule_id ?? artifact.id).replace(/[^a-zA-Z0-9._-]/g, "-");
  const ext = FILE_EXTENSIONS[artifact.language] ?? "txt";
  return `${base}.${ext}`;
}
