import { describe, expect, it } from "vitest";
import type { DetectionArtifact } from "./api";
import { readDetectionVersions, withDetectionVersion } from "./detectionVersioning";

const artifact = (overrides: Partial<DetectionArtifact> = {}) => ({
  id: "det_test", language: "sigma", target: { language: "sigma", platform: "generic", product: null }, title: "Test", description: "", content: "title: Test", severity: 2, category: "generic", capabilities: [], source_finding_ids: [], references: [], validation: { status: "valid", validator: null, messages: [] }, review_status: "draft", review_note: "", reviewed_at: null, reviewed_by: null, rule_id: "r_test", metadata: {}, ...overrides,
} as DetectionArtifact);

describe("detection version history", () => {
  it("records meaningful changes", () => {
    const first = artifact();
    expect(withDetectionVersion(first, first)).toEqual(first);
    const second = withDetectionVersion(first, artifact({ content: "title: Changed" }));
    expect(readDetectionVersions(second)[0].version).toBe(1);
    expect(readDetectionVersions(second)[0].changed_fields).toContain("content");
  });
});
