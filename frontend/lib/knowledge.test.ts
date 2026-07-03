import { describe, expect, it } from "vitest";

import type { CommunityRule } from "./api";
import {
  communityRuleFilename,
  isRedistributable,
  licenseSupportLabel,
  matchTypeClass,
  matchTypeLabel,
  matchTypeOrder,
  similarityClass,
} from "./knowledge";

describe("matchTypeLabel", () => {
  it("labels each match strength", () => {
    expect(["exact", "partial", "related", "none"].map(matchTypeLabel)).toEqual([
      "Exact match",
      "Partial match",
      "Related",
      "No match",
    ]);
  });
});

describe("matchTypeOrder", () => {
  it("ranks exact before partial before related", () => {
    expect(matchTypeOrder("exact")).toBeLessThan(matchTypeOrder("partial"));
    expect(matchTypeOrder("partial")).toBeLessThan(matchTypeOrder("related"));
  });
});

describe("matchTypeClass", () => {
  it("returns distinct classes per match type", () => {
    expect(matchTypeClass("exact")).toContain("emerald");
    expect(matchTypeClass("partial")).toContain("sky");
  });
});

describe("similarityClass", () => {
  it("buckets scores into colour classes", () => {
    expect(similarityClass(90)).toContain("emerald");
    expect(similarityClass(50)).toContain("sky");
    expect(similarityClass(20)).toContain("amber");
    expect(similarityClass(5)).toContain("zinc");
  });
});

describe("licenses", () => {
  it("labels every support level", () => {
    expect(licenseSupportLabel("permissive")).toBe("Permissive");
    expect(licenseSupportLabel("restricted")).toBe("Restricted");
    expect(licenseSupportLabel("unsupported")).toBe("Unsupported");
  });

  it("only permits redistribution for permissive/copyleft", () => {
    expect(isRedistributable("permissive")).toBe(true);
    expect(isRedistributable("copyleft")).toBe(true);
    expect(isRedistributable("restricted")).toBe(false);
    expect(isRedistributable("unsupported")).toBe(false);
  });
});

describe("communityRuleFilename", () => {
  const rule = {
    id: "com_abc",
    rule_id: "ET TROJAN/2400001",
    language: "suricata",
  } as unknown as CommunityRule;

  it("sanitizes the rule id and maps the language extension", () => {
    expect(communityRuleFilename(rule)).toBe("ET-TROJAN-2400001.rules");
  });

  it("falls back to .txt for an unknown language", () => {
    const unknown = { ...rule, language: "mystery" } as unknown as CommunityRule;
    expect(communityRuleFilename(unknown)).toBe("ET-TROJAN-2400001.txt");
  });
});
