import { describe, expect, it } from "vitest";

import type { Finding } from "@/lib/api";
import { summarizeProviders } from "./ReportThreatIntelligence";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_1",
    title: "Test finding",
    categories: [],
    subject_type: "ipv4",
    subject_value: "1.2.3.4",
    severity: 2,
    confidence: { score: 70, band: "moderate", contested: false, factors: [] },
    priority: 0,
    evidence: [],
    relationships: [],
    sources: [],
    rationale: "",
    rule_ids: [],
    recommendations: [],
    ...overrides,
  };
}

describe("summarizeProviders", () => {
  it("returns an empty list when no finding has any evidence or relationships", () => {
    expect(summarizeProviders([finding()])).toEqual([]);
  });

  it("counts one evidence item toward its reporting provider", () => {
    const f = finding({
      evidence: [
        {
          evidence: { evidence: { type: "other", summary: "x", value: null, confidence: null, observed_at: null, data: {} }, sources: ["abuseipdb"] },
          weight: 1,
          polarity: "supporting",
          dimension: "reputation",
        },
      ],
    });
    const result = summarizeProviders([f]);
    expect(result).toEqual([
      { provider: "abuseipdb", evidenceCount: 1, relationshipCount: 0, findingTitles: ["Test finding"] },
    ]);
  });

  it("counts one relationship toward its reporting provider", () => {
    const f = finding({
      relationships: [
        {
          relationship: { relationship: "uses", target_type: "malware_family", target_value: "Emotet", confidence: null, description: null },
          sources: ["otx"],
        },
      ],
    });
    const result = summarizeProviders([f]);
    expect(result).toEqual([
      { provider: "otx", evidenceCount: 0, relationshipCount: 1, findingTitles: ["Test finding"] },
    ]);
  });

  it("attributes one evidence item to every provider that reported it", () => {
    const f = finding({
      evidence: [
        {
          evidence: { evidence: { type: "other", summary: "x", value: null, confidence: null, observed_at: null, data: {} }, sources: ["abuseipdb", "otx"] },
          weight: 1,
          polarity: "supporting",
          dimension: "reputation",
        },
      ],
    });
    const result = summarizeProviders([f]);
    expect(result.map((p) => p.provider)).toEqual(["abuseipdb", "otx"]);
    expect(result.every((p) => p.evidenceCount === 1)).toBe(true);
  });

  it("sorts providers alphabetically regardless of finding order", () => {
    const f1 = finding({
      id: "fnd_1",
      title: "F1",
      evidence: [
        {
          evidence: { evidence: { type: "other", summary: "x", value: null, confidence: null, observed_at: null, data: {} }, sources: ["zzz_provider"] },
          weight: 1,
          polarity: "supporting",
          dimension: "reputation",
        },
      ],
    });
    const f2 = finding({
      id: "fnd_2",
      title: "F2",
      evidence: [
        {
          evidence: { evidence: { type: "other", summary: "y", value: null, confidence: null, observed_at: null, data: {} }, sources: ["aaa_provider"] },
          weight: 1,
          polarity: "supporting",
          dimension: "reputation",
        },
      ],
    });
    expect(summarizeProviders([f1, f2]).map((p) => p.provider)).toEqual([
      "aaa_provider",
      "zzz_provider",
    ]);
  });

  it("lists each contributing finding's title only once per provider", () => {
    const evidenceFrom = (source: string) => ({
      evidence: { evidence: { type: "other", summary: "x", value: null, confidence: null, observed_at: null, data: {} }, sources: [source] },
      weight: 1,
      polarity: "supporting" as const,
      dimension: "reputation",
    });
    const f = finding({ title: "Repeated", evidence: [evidenceFrom("otx"), evidenceFrom("otx")] });
    const result = summarizeProviders([f]);
    expect(result).toEqual([
      { provider: "otx", evidenceCount: 2, relationshipCount: 0, findingTitles: ["Repeated"] },
    ]);
  });
});
