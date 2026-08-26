import type { DetectionArtifact } from "./api";

export interface DetectionVersionSnapshot {
  version: number;
  artifact_id: string;
  content: string;
  changed_fields: string[];
  mapping_version: string;
  engine_version: string;
  created_at: string;
  reviewer: string | null;
  approved: boolean;
}

const HISTORY_KEY = "version_history";

function changedFields(previous: DetectionArtifact, current: DetectionArtifact): string[] {
  const fields = ["content", "title", "description", "severity", "category", "metadata"] as const;
  return fields.filter((field) => JSON.stringify(previous[field]) !== JSON.stringify(current[field]));
}

export function readDetectionVersions(artifact: DetectionArtifact): DetectionVersionSnapshot[] {
  try {
    const value = JSON.parse(artifact.metadata?.[HISTORY_KEY] ?? "[]") as DetectionVersionSnapshot[];
    return Array.isArray(value) ? value.filter((item) => item && typeof item.version === "number") : [];
  } catch { return []; }
}

export function withDetectionVersion(previous: DetectionArtifact, current: DetectionArtifact, reviewer: string | null = "local-analyst"): DetectionArtifact {
  const changed = changedFields(previous, current);
  if (changed.length === 0) return current;
  const history = readDetectionVersions(previous);
  const snapshot: DetectionVersionSnapshot = {
    version: (history.at(-1)?.version ?? 0) + 1,
    artifact_id: current.id,
    content: current.content,
    changed_fields: changed,
    mapping_version: current.metadata?.mapping_version ?? "default",
    engine_version: current.metadata?.engine_version ?? "unknown",
    created_at: new Date().toISOString(),
    reviewer,
    approved: current.review_status === "approved",
  };
  return { ...current, metadata: { ...current.metadata, [HISTORY_KEY]: JSON.stringify([...history, snapshot]) } };
}

export function versionHistoryExportName(artifact: DetectionArtifact, version: number): string {
  return `${(artifact.rule_id || artifact.id).replace(/[^a-zA-Z0-9_.-]+/g, "_")}.v${version}`;
}
