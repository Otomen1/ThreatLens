import { describe, expect, it } from "vitest";

import type { AttributedReference, AttributedRelationship, Finding } from "./api";
import {
  findingsByIds,
  groupKeyAttributes,
  groupReferencesBySource,
  groupRelationshipsByTarget,
  type KeyAttribute,
} from "./investigation";

function finding(id: string): Finding {
  return { id, title: id } as unknown as Finding;
}

describe("findingsByIds", () => {
  it("returns the matching findings in the requested id order", () => {
    const findings = [finding("a"), finding("b"), finding("c")];
    expect(findingsByIds(findings, ["c", "a"]).map((f) => f.id)).toEqual(["c", "a"]);
  });

  it("skips ids that have no matching finding", () => {
    const findings = [finding("a")];
    expect(findingsByIds(findings, ["a", "missing"]).map((f) => f.id)).toEqual(["a"]);
  });

  it("returns an empty array for no ids", () => {
    expect(findingsByIds([finding("a")], [])).toEqual([]);
  });
});

describe("groupKeyAttributes", () => {
  const attr = (label: string, value = "x"): KeyAttribute => ({ label, value });

  it("groups known reference labels into their canonical category", () => {
    const groups = groupKeyAttributes([attr("Tactics"), attr("CVSS Score"), attr("Aliases")]);
    expect(groups.map((g) => g.category)).toEqual(["Threat Actors", "Techniques", "Vulnerabilities"]);
  });

  it("only returns categories that contain data", () => {
    const groups = groupKeyAttributes([attr("Tactics")]);
    expect(groups).toHaveLength(1);
    expect(groups[0].category).toBe("Techniques");
  });

  it("falls back to a substring heuristic for dynamic IOC evidence labels", () => {
    const groups = groupKeyAttributes([attr("Malware Family"), attr("Distinct Reporters")]);
    const byCategory = Object.fromEntries(groups.map((g) => [g.category, g.items.length]));
    expect(byCategory["Malware Families"]).toBe(1);
    expect(byCategory["Other"]).toBe(1);
  });

  it("returns an empty array for no attributes", () => {
    expect(groupKeyAttributes([])).toEqual([]);
  });

  it("never merges or drops attributes", () => {
    const input = [attr("Tactics", "a"), attr("Tactics", "b"), attr("Platforms", "c")];
    const groups = groupKeyAttributes(input);
    const total = groups.reduce((n, g) => n + g.items.length, 0);
    expect(total).toBe(input.length);
  });
});

function relationship(targetType: string, targetValue: string): AttributedRelationship {
  return {
    relationship: { relationship: "uses", target_type: targetType, target_value: targetValue, confidence: null, description: null },
    sources: ["otx"],
  };
}

describe("groupRelationshipsByTarget", () => {
  it("groups relationships by target type with a human label", () => {
    const groups = groupRelationshipsByTarget([
      relationship("attack_pattern", "T1071"),
      relationship("attack_pattern", "T1204"),
      relationship("malware_family", "Emotet"),
    ]);
    expect(groups[0]).toMatchObject({ targetType: "attack_pattern", label: "Technique" });
    expect(groups[0].items).toHaveLength(2);
    expect(groups[1]).toMatchObject({ targetType: "malware_family", label: "Malware" });
  });

  it("orders larger groups first", () => {
    const groups = groupRelationshipsByTarget([
      relationship("malware_family", "a"),
      relationship("attack_pattern", "b"),
      relationship("attack_pattern", "c"),
    ]);
    expect(groups.map((g) => g.targetType)).toEqual(["attack_pattern", "malware_family"]);
  });

  it("returns an empty array for no relationships", () => {
    expect(groupRelationshipsByTarget([])).toEqual([]);
  });
});

function reference(source: string, url: string): AttributedReference {
  return { reference: { title: url, url, description: null }, sources: [source] };
}

describe("groupReferencesBySource", () => {
  it("groups references by their primary source", () => {
    const groups = groupReferencesBySource([
      reference("otx", "https://a"),
      reference("otx", "https://b"),
      reference("mitre_attack", "https://c"),
    ]);
    expect(groups[0]).toMatchObject({ source: "otx", label: "otx" });
    expect(groups[0].items).toHaveLength(2);
  });

  it("humanizes underscored source names", () => {
    const groups = groupReferencesBySource([reference("mitre_attack", "https://c")]);
    expect(groups[0].label).toBe("mitre attack");
  });

  it("falls back to 'other' when a reference has no source", () => {
    const groups = groupReferencesBySource([{ reference: { title: "x", url: "https://x", description: null }, sources: [] }]);
    expect(groups[0].source).toBe("other");
  });

  it("returns an empty array for no references", () => {
    expect(groupReferencesBySource([])).toEqual([]);
  });
});
