import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { FeedBadge, FeedSeverityBadge } from "./FeedBadge";

describe("consistent source-backed feed badges", () => {
  it("uses neutral styling when severity is not supplied", () => {
    const html = renderToStaticMarkup(createElement(FeedSeverityBadge, { severity: null }));
    expect(html).toContain("Not rated");
    expect(html).toContain("text-zinc-300");
    expect(html).not.toMatch(/text-(?:amber|red)-/);
  });
  it("preserves supplied severity without inventing a rating for other values", () => {
    expect(renderToStaticMarkup(createElement(FeedSeverityBadge, { severity: "CRITICAL" }))).toMatch(/text-red-300.*critical/);
    expect(renderToStaticMarkup(createElement(FeedSeverityBadge, { severity: "informational" }))).toMatch(/text-zinc-300.*informational/);
  });
  it("keeps labels escaped and uses one readable badge size", () => {
    const html = renderToStaticMarkup(createElement(FeedBadge, null, "<script>Source label</script>"));
    expect(html).toContain("text-[11px]");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
  });
});
