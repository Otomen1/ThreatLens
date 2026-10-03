import { describe, expect, it, vi, afterEach } from "vitest";
import { defang, exportIocs, readIocCache, writeIocCache, localReportState } from "./iocReports";
import type { IocReport, IocReportList } from "./api/iocReports";

const report: IocReport = { id: "one", vendor: "eset", title: "=Formula", path: "iocs.txt", source_url: "https://github.com/eset/malware-ioc/blob/master/iocs.txt", article_url: null, published_at: null, activity_at: new Date().toISOString(), collected_at: new Date().toISOString(), commit: "a".repeat(40), blob: "a".repeat(40), parser_version: "1.0", license: "BSD-2-Clause", license_url: "https://github.com/eset/malware-ioc/blob/master/LICENSE", attribution: "ESET", indicator_count: 1, types: ["domain"], warnings: [], withdrawn: false };
const result: IocReportList = { items: [report], total: 1, page: 1, page_size: 20, unique_indicators: 1, recent_indicators: 1, sources: [], generated_at: new Date().toISOString() };
function storage() { const values = new Map<string, string>(); vi.stubGlobal("localStorage", { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) }); return values; }
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
describe("IOC report privacy and exports", () => {
  it("defangs without altering case or URL paths", () => { expect(defang("https://example.com/Case")).toBe("hxxps://example[.]com/Case"); });
  it("includes provenance and full license notices and escapes spreadsheet formulas", () => {
    const items = [{ id: "ioc", type: "domain", value: "evil.test", original: "evil[.]test", verified: false as const, disposition: "source-reported" as const }];
    const json = JSON.parse(exportIocs(report, items, "json"));
    expect(json.license_notice).toContain("Redistribution and use");
    expect(json.verification).toContain("not independently verified");
    expect(exportIocs(report, items, "csv")).toContain("'=Formula");
    expect(JSON.stringify(json)).not.toContain("access_token");
  });
  it("hydrates only matching versioned caches, expires at 24h and rejects corrupt data", () => {
    const values = storage(); vi.useFakeTimers(); writeIocCache("reports", result);
    expect(readIocCache("reports")).toEqual(result); expect(readIocCache("other")).toBeNull();
    vi.advanceTimersByTime(86400001); expect(readIocCache("reports")).toBeNull();
    values.set("threatlens.feed.iocs.v1", "bad"); expect(readIocCache("reports")).toBeNull();
  });
  it("stores only browser-local read and bookmark identifiers", () => { const values = storage(); localReportState("read", "one"); expect(localReportState("bookmark", "one")).toBe(true); expect(localReportState("isBookmarked", "one")).toBe(true); expect(localReportState("bookmark", "one")).toBe(false); expect([...values.values()].join()).not.toContain("evil.test"); });
});
