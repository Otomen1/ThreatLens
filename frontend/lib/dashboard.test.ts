import { describe, expect, it } from "vitest";

import {
  formatBytes,
  formatLatency,
  formatNumber,
  formatPercent,
  formatTimestamp,
  statusBadgeClasses,
  statusDotClass,
  statusLabel,
} from "./dashboard";

describe("statusBadgeClasses / statusDotClass / statusLabel", () => {
  it("maps healthy to an emerald/green treatment", () => {
    expect(statusBadgeClasses("healthy")).toContain("emerald");
    expect(statusDotClass("healthy")).toContain("emerald");
    expect(statusLabel("healthy")).toBe("Healthy");
  });

  it("maps degraded to an amber/yellow treatment", () => {
    expect(statusBadgeClasses("degraded")).toContain("amber");
    expect(statusDotClass("degraded")).toContain("amber");
    expect(statusLabel("degraded")).toBe("Degraded");
  });

  it("maps offline to a red treatment", () => {
    expect(statusBadgeClasses("offline")).toContain("red");
    expect(statusDotClass("offline")).toContain("red");
    expect(statusLabel("offline")).toBe("Offline");
  });

  it("maps disabled to a gray/zinc treatment", () => {
    expect(statusBadgeClasses("disabled")).toContain("zinc");
    expect(statusDotClass("disabled")).toContain("zinc");
    expect(statusLabel("disabled")).toBe("Disabled");
  });
});

describe("formatLatency", () => {
  it("renders sub-second latency in milliseconds", () => {
    expect(formatLatency(142)).toBe("142 ms");
  });

  it("renders >= 1000ms in seconds with one decimal", () => {
    expect(formatLatency(1234)).toBe("1.2 s");
  });

  it("renders a dash for null", () => {
    expect(formatLatency(null)).toBe("—");
  });
});

describe("formatPercent", () => {
  it("renders one decimal place with a percent sign", () => {
    expect(formatPercent(98.456)).toBe("98.5%");
  });

  it("renders a dash for null", () => {
    expect(formatPercent(null)).toBe("—");
  });
});

describe("formatBytes", () => {
  it("renders 0 bytes literally", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("renders sub-1024 byte counts as B", () => {
    expect(formatBytes(512)).toBe("512 B");
  });

  it("renders kilobytes with one decimal", () => {
    expect(formatBytes(1536)).toBe("1.5 KB");
  });

  it("renders megabytes with one decimal", () => {
    expect(formatBytes(2 * 1024 * 1024)).toBe("2.0 MB");
  });

  it("renders a dash for null", () => {
    expect(formatBytes(null)).toBe("—");
  });
});

describe("formatTimestamp", () => {
  it("renders a dash for null", () => {
    expect(formatTimestamp(null)).toBe("—");
  });

  it("renders a dash for an unparseable string", () => {
    expect(formatTimestamp("not-a-date")).toBe("—");
  });

  it("renders a valid ISO timestamp as a locale string", () => {
    const out = formatTimestamp("2024-06-01T12:30:00Z");
    expect(out).not.toBe("—");
    expect(out).toContain("2024");
  });
});

describe("formatNumber", () => {
  it("renders a dash for null", () => {
    expect(formatNumber(null)).toBe("—");
  });

  it("trims trailing zeros", () => {
    expect(formatNumber(3.0)).toBe("3");
  });

  it("keeps significant decimals", () => {
    expect(formatNumber(3.456, 2)).toBe("3.46");
  });
});
