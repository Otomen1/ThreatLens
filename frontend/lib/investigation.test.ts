import { describe, expect, it } from "vitest";

import type { Finding } from "./api";
import { findingsByIds } from "./investigation";

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
