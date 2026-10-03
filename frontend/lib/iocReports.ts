import type { Ioc, IocReport, IocReportList, IocIndicatorList } from "./api/iocReports";

const CACHE = "threatlens.feed.iocs.v1";
function validReport(item: unknown): item is IocReport {
  if (!item || typeof item !== "object") return false;
  const r = item as IocReport;
  return [r.id, r.title, r.vendor, r.path, r.source_url, r.activity_at, r.collected_at].every((v) => typeof v === "string") && r.source_url.startsWith("https://github.com/") && Array.isArray(r.warnings) && r.warnings.every((v) => typeof v === "string") && Array.isArray(r.types) && Number.isInteger(r.indicator_count) && r.indicator_count >= 0 && Number.isFinite(Date.parse(r.activity_at));
}
function validList(value: unknown): value is IocReportList | IocIndicatorList {
  if (!value || typeof value !== "object") return false;
  const d = value as IocReportList | IocIndicatorList;
  if (!Array.isArray(d.items) || ![d.total, d.page, d.page_size].every((v) => Number.isInteger(v) && v >= 0) || d.page < 1 || d.page_size < 1) return false;
  if ("sources" in d) return Array.isArray(d.sources) && d.sources.every((s) => s && typeof s.vendor === "string" && typeof s.status === "string" && typeof s.name === "string") && typeof d.generated_at === "string" && d.items.every(validReport);
  return d.items.every((i) => i && typeof i.value === "string" && typeof i.type === "string" && typeof i.id === "string" && Array.isArray(i.vendors) && Array.isArray(i.reports) && i.reports.every(validReport));
}
export function defang(value: string) { return value.replace(/^http/i, "hxxp").replaceAll(".", "[.]"); }
export function readIocCache(key: string): IocReportList | IocIndicatorList | null {
  try {
    const stored = JSON.parse(localStorage.getItem(CACHE) ?? "null");
    if (!stored) return null;
    if (stored.version !== 1 || !Number.isFinite(stored.savedAt) || stored.savedAt > Date.now() || Date.now() - stored.savedAt > 86400000 || !validList(stored.data)) { localStorage.removeItem(CACHE); return null; }
    return stored.key === key ? stored.data : null;
  } catch { try { localStorage.removeItem(CACHE); } catch { /* Optional storage. */ } return null; }
}
export function writeIocCache(key: string, data: IocReportList | IocIndicatorList) {
  try { const serialized = JSON.stringify({ version: 1, key, savedAt: Date.now(), data }); if (serialized.length <= 250000) localStorage.setItem(CACHE, serialized); } catch { /* Optional compact browser cache. */ }
}
export function localReportState(action: "read" | "bookmark" | "isBookmarked", id: string): boolean {
  const key = `threatlens.feed.iocs.${action === "read" ? "viewed" : "bookmarks"}`;
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(key) ?? "[]");
    const ids = new Set<string>(Array.isArray(raw) ? raw.filter((v) => typeof v === "string") : []);
    if (action === "isBookmarked") return ids.has(id);
    if (action === "bookmark" && ids.has(id)) ids.delete(id); else ids.add(id);
    localStorage.setItem(key, JSON.stringify([...ids].slice(-500)));
    return ids.has(id);
  } catch { return false; }
}
const ESET_NOTICE = `Copyright (c) 2014-2018 ESET spol. s r.o. All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`;
function csvCell(value: string) { return `"${(/^[\s]*[=+\-@\t\r]/.test(value) ? "'" : "") + value.replaceAll('"', '""')}"`; }
export function exportIocs(report: IocReport, items: Ioc[], format: "json" | "csv") {
  const metadata = { schema_version: 1, exported_at: new Date().toISOString(), values: "normalized", verification: "Source-reported; not independently verified; current activity unknown", report, license_notice: report.vendor === "eset" ? ESET_NOTICE : `${report.license}: ${report.license_url}` };
  if (format === "json") return JSON.stringify({ ...metadata, indicators: items }, null, 2);
  const rows = [["type", "value", "original", "vendor", "report", "source", "updated", "verification", "license", "license_notice"], ...items.map((i) => [i.type, i.value, i.original, report.vendor, report.title, report.source_url, report.activity_at, metadata.verification, report.license, metadata.license_notice])];
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}
export function downloadIocs(report: IocReport, items: Ioc[], format: "json" | "csv") {
  const url = URL.createObjectURL(new Blob([exportIocs(report, items, format)], { type: format === "json" ? "application/json" : "text/csv;charset=utf-8" }));
  const link = document.createElement("a"); link.href = url; link.download = `threatlens-iocs-${report.id}.${format}`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
