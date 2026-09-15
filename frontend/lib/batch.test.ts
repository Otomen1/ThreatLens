import { describe, expect, it } from "vitest";

import { riskLabel, rowsToCsv } from "./batch";

describe("batch export helpers", () => {
  it("labels all posture levels", () => {
    expect([0, 1, 2, 3, 4].map(riskLabel)).toEqual(["Unknown", "Low", "Medium", "High", "Critical"]);
  });

  it("escapes CSV values without exposing extra fields", () => {
    const csv = rowsToCsv([{ value: 'evil,"domain"', type: "domain", state: "failed", errorCode: "timeout" }]);
    expect(csv).toContain('"evil,""domain"""');
    expect(csv).toContain("timeout");
    expect(csv).not.toContain("stack");
  });
});
