import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import type { InvestigationResponse, InvestigationSummary } from "@/lib/api";
import { ResultOverview } from "./ResultOverview";
const summary = { entity_value: "example.test", posture: 3, overall_confidence: { band: "moderate", score: 54, contested: true }, findings: Array.from({ length: 5 }, (_, i) => ({ id: String(i), title: `Finding ${i}` })), recommendations: [{ action: "Inspect evidence" }] } as InvestigationSummary;
it("keeps old summary-only records honest and bounds key findings", () => {
  const html = renderToStaticMarkup(createElement(ResultOverview, { summary, saved: true, scope: "unique" }));
  expect(html).toContain("Summary-only record"); expect(html).toContain("Saved to database"); expect(html).toContain('href="#unique-findings"'); expect(html).not.toContain("Finding 3"); expect(html).not.toContain("safe verdict");
});
it("shows cached, partial and conflicting coverage without changing assessment scores", () => {
  const data = { threat_intelligence: { providers: [{ provider: "otx", status: "timeout" }], agreement: { conflicted: true } }, cache: { status: "hit", age_seconds: 20, expires_at: "2026-01-01T12:00:00Z" } } as unknown as InvestigationResponse;
  const html = renderToStaticMarkup(createElement(ResultOverview, { summary, data }));
  expect(html).toContain("Partial coverage"); expect(html).toContain("Conflicting evidence"); expect(html).toContain("20s old"); expect(html).toContain("(54)"); expect(html).toContain("Temporary");
});
