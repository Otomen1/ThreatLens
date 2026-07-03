import { describe, expect, it } from "vitest";

import type { DetectionArtifact } from "./api";
import {
  artifactFilename,
  detectionLanguageLabel,
  detectionSeverityLabel,
  groupByLanguage,
  mitreFromMetadata,
  mitreTechniqueUrl,
} from "./detection";

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

  it("uses a .yar extension for yara and falls back to the artifact id", () => {
    const artifact = { id: "det_x", language: "yara", rule_id: null } as unknown as DetectionArtifact;
    expect(artifactFilename(artifact)).toBe("det_x.yar");
  });

  it("uses .rules for suricata and snort", () => {
    const suricata = { id: "det_s", language: "suricata", rule_id: "sur_1" } as unknown as DetectionArtifact;
    const snort = { id: "det_n", language: "snort", rule_id: "snr_1" } as unknown as DetectionArtifact;
    expect(artifactFilename(suricata)).toBe("sur_1.rules");
    expect(artifactFilename(snort)).toBe("snr_1.rules");
  });

  it("uses native extensions for SIEM languages", () => {
    const cases: Array<[string, string]> = [
      ["splunk_spl", "spl"],
      ["sentinel_kql", "kql"],
      ["elastic_esql", "esql"],
      ["chronicle_yara_l", "yaral"],
      ["qradar_aql", "aql"],
    ];
    for (const [language, ext] of cases) {
      const artifact = { id: "det_x", language, rule_id: "r_1" } as unknown as DetectionArtifact;
      expect(artifactFilename(artifact)).toBe(`r_1.${ext}`);
    }
  });

  it("falls back to .txt for unknown languages", () => {
    const artifact = { id: "det_z", language: "crowdstrike", rule_id: null } as unknown as DetectionArtifact;
    expect(artifactFilename(artifact)).toBe("det_z.txt");
  });
});

describe("detectionLanguageLabel", () => {
  it("uses the exact display names analysts expect", () => {
    expect(detectionLanguageLabel("sigma")).toBe("Sigma");
    expect(detectionLanguageLabel("yara")).toBe("YARA");
    expect(detectionLanguageLabel("splunk_spl")).toBe("Splunk SPL");
    expect(detectionLanguageLabel("sentinel_kql")).toBe("Sentinel KQL");
    expect(detectionLanguageLabel("elastic_esql")).toBe("Elastic ES|QL");
    expect(detectionLanguageLabel("chronicle_yara_l")).toBe("Chronicle YARA-L");
    expect(detectionLanguageLabel("qradar_aql")).toBe("QRadar AQL");
  });
});

function artifact(language: string, id: string): DetectionArtifact {
  return { id, language, rule_id: id } as unknown as DetectionArtifact;
}

describe("groupByLanguage", () => {
  it("groups items by language, only including languages present", () => {
    const items = [artifact("yara", "a"), artifact("sigma", "b"), artifact("sigma", "c")];
    const groups = groupByLanguage(items);
    expect(groups.map((g) => g.language)).toEqual(["sigma", "yara"]);
    expect(groups[0].items.map((i) => i.id)).toEqual(["b", "c"]);
    expect(groups[0].items.length).toBe(2);
  });

  it("orders groups canonically (Sigma before YARA before network before SIEM)", () => {
    const items = [artifact("qradar_aql", "a"), artifact("yara", "b"), artifact("sigma", "c")];
    const groups = groupByLanguage(items);
    expect(groups.map((g) => g.language)).toEqual(["sigma", "yara", "qradar_aql"]);
  });

  it("preserves item order within a group (severity-sorted upstream)", () => {
    const items = [artifact("sigma", "high"), artifact("sigma", "low")];
    const groups = groupByLanguage(items);
    expect(groups[0].items.map((i) => i.id)).toEqual(["high", "low"]);
  });

  it("returns an empty array for no items", () => {
    expect(groupByLanguage([])).toEqual([]);
  });
});

describe("mitreFromMetadata", () => {
  it("reads the attack key (Sigma/YARA/network generators)", () => {
    expect(mitreFromMetadata({ attack: "T1071,T1204.002" })).toEqual(["T1071", "T1204.002"]);
  });

  it("falls back to the mitre key (SIEM generators)", () => {
    expect(mitreFromMetadata({ mitre: "T1059.001" })).toEqual(["T1059.001"]);
  });

  it("treats Chronicle's n/a marker and blanks as no techniques", () => {
    expect(mitreFromMetadata({ mitre: "n/a" })).toEqual([]);
    expect(mitreFromMetadata({})).toEqual([]);
  });
});

describe("mitreTechniqueUrl", () => {
  it("links to the technique page", () => {
    expect(mitreTechniqueUrl("T1071")).toBe("https://attack.mitre.org/techniques/T1071/");
  });

  it("links to the sub-technique page", () => {
    expect(mitreTechniqueUrl("T1204.002")).toBe("https://attack.mitre.org/techniques/T1204/002/");
  });
});
