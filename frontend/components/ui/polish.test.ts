import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
import { FilterSummary } from "./FilterSummary";
import { CopyButton } from "./CopyButton";
import { ToastProvider } from "./ToastProvider";
import { ActionToolbar } from "./ActionToolbar";

it("counts effective filters and gives each chip an accessible removal action", () => {
  const action = vi.fn();
  const html = renderToStaticMarkup(createElement(FilterSummary, { filters: [{ key: "severity", label: "Severity", value: "High", remove: action }], reset: action }));
  expect(html).toContain("1 filter active"); expect(html).toContain('aria-label="Remove Severity filter"'); expect(html).toContain("Reset filters"); expect(action).not.toHaveBeenCalled();
  const empty = renderToStaticMarkup(createElement(FilterSummary, { filters: [], reset: action }));
  expect(empty).toContain("0 filters active"); expect(empty).not.toContain("Reset filters");
});
it("renders a stable copy label, fixed icon slot and accessible feedback region", () => {
  const html = renderToStaticMarkup(createElement(ToastProvider, null, createElement(CopyButton, { value: "fixture", label: "Copy rule" })));
  expect(html).toContain('aria-label="Copy rule"'); expect(html).toContain('data-copied="false"'); expect(html).toContain("h-4 w-4 shrink-0"); expect(html).toContain('role="status"'); expect(html).not.toContain("fixture");
});
it("keeps context and actions in the shared responsive toolbar", () => {
  const html = renderToStaticMarkup(createElement(ActionToolbar, { context: "3 selected" }, createElement("button", null, "Export")));
  expect(html).toContain("ui-action-toolbar"); expect(html).toContain("ui-toolbar-actions"); expect(html).toContain("3 selected"); expect(html).toContain("Export");
});
