import { describe, expect, it } from "vitest";

import { sanitizeFilenameSegment } from "./download";

describe("sanitizeFilenameSegment", () => {
  it("passes through an already-safe UUID unchanged", () => {
    expect(sanitizeFilenameSegment("b6b25169-8d22-4503-b53c-0f59ff38c992")).toBe(
      "b6b25169-8d22-4503-b53c-0f59ff38c992",
    );
  });

  it("strips path separators and other unsafe characters", () => {
    expect(sanitizeFilenameSegment("../../etc/passwd")).toBe("etcpasswd");
    expect(sanitizeFilenameSegment("a/b\\c")).toBe("abc");
  });

  it("strips whitespace and punctuation", () => {
    expect(sanitizeFilenameSegment("hello world!.json")).toBe("helloworldjson");
  });

  it("leaves an empty string empty", () => {
    expect(sanitizeFilenameSegment("")).toBe("");
  });
});
