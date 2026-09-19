import { describe, expect, it, vi } from "vitest";

import { checkPasswordExposure } from "./passwordExposure";

describe("checkPasswordExposure", () => {
  it("sends only the five-character prefix and matches locally", async () => {
    const lookup = vi.fn(async (prefix: string) => ({
      prefix,
      suffixes: [{ suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8", count: 42 }],
      checked_at: "2026-01-01T00:00:00Z",
    }));

    await expect(checkPasswordExposure("password", lookup)).resolves.toBe(42);
    expect(lookup).toHaveBeenCalledWith("5BAA6");
    expect(lookup.mock.calls[0]?.[0]).toHaveLength(5);
  });

  it("returns zero when the suffix is absent", async () => {
    const lookup = vi.fn(async (prefix: string) => ({
      prefix,
      suffixes: [],
      checked_at: "2026-01-01T00:00:00Z",
    }));
    await expect(checkPasswordExposure("unique-value", lookup)).resolves.toBe(0);
  });
});
