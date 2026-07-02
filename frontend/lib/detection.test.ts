import { describe, expect, it } from "vitest";

import type { DetectionArtifact } from "./api";
import { artifactFilename, detectionSeverityLabel } from "./detection";

describe("detectionSeverityLabel", () => {
  it("maps ordinal severities to labels", () => {
    expect([0, 1, 2, 3, 4].map(detectionSeverityLabel)).toEqual([
      "Informational",
      "Low",
      "Medium",
      "High",
      "Critical",
    ]);
  });

  it("falls back to Unknown for out-of-range values", () => {
    expect(detectionSeverityLabel(9)).toBe("Unknown");
  });
});

describe("artifactFilename", () => {
  const base = {
    id: "det_abc",
    language: "sigma",
    rule_id: "646fb072-055e-57f5-884e-dc3d85885caf",
  } as unknown as DetectionArtifact;

  it("uses the rule id and a .yml extension for sigma", () => {
    expect(artifactFilename(base)).toBe("646fb072-055e-57f5-884e-dc3d85885caf.yml");
  });

  it("sanitizes unsafe characters and falls back to the artifact id", () => {
    const artifact = { id: "det_x", language: "yara", rule_id: null } as unknown as DetectionArtifact;
    expect(artifactFilename(artifact)).toBe("det_x.txt");
  });
});
