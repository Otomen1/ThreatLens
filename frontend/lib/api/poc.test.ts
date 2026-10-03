import { expect, it } from "vitest";
import { normalizePocCve } from "./poc";

it("normalizes one CVE and rejects prose, lists and unicode digits", () => {
  expect(normalizePocCve(" cve-2021-44228 ")).toBe("CVE-2021-44228");
  for (const value of ["CVE-2021-123", "CVE-2021-44228,CVE-2022-12345", "https://example.test", "CVE-２０２１-４４２２８"]) expect(normalizePocCve(value)).toBeNull();
});
