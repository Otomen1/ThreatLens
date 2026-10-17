export type FeedTable = "news" | "vulnerability" | "ioc" | "indicators";
export const FEED_COLUMNS: Record<FeedTable, Record<string, string>> = {
  news: { source: "Source", age: "Age", category: "Category", severity: "Severity" },
  vulnerability: { product: "Affected product", source: "Source", published: "Published", severity: "Severity / CVSS", exploitation: "Exploitation" },
  ioc: { vendor: "Vendor", dates: "Published / updated", count: "IOC count" },
  indicators: { type: "Type", vendor: "Vendors", reports: "Supporting reports" },
};
export type FeedDisplay = { density: "compact" | "comfortable"; hidden: Partial<Record<FeedTable, string[]>> };
export const FEED_DISPLAY_KEY = "threatlens.feed.display.v1";
export const DEFAULT_FEED_DISPLAY: FeedDisplay = { density: "compact", hidden: {} };
export function readFeedDisplay(): FeedDisplay {
  try {
    const raw = JSON.parse(localStorage.getItem(FEED_DISPLAY_KEY) ?? "null");
    if (raw?.version !== 1 || !raw.value || typeof raw.value !== "object") return DEFAULT_FEED_DISPLAY;
    const hidden: FeedDisplay["hidden"] = {};
    for (const table of Object.keys(FEED_COLUMNS) as FeedTable[]) {
      const values: unknown = raw.value.hidden?.[table];
      if (Array.isArray(values)) hidden[table] = [...new Set(values.filter((v): v is string => typeof v === "string" && Object.hasOwn(FEED_COLUMNS[table], v)))];
    }
    return { density: raw.value.density === "comfortable" ? "comfortable" : "compact", hidden };
  } catch { return DEFAULT_FEED_DISPLAY; }
}
export function writeFeedDisplay(value: FeedDisplay): boolean {
  try { localStorage.setItem(FEED_DISPLAY_KEY, JSON.stringify({ version: 1, value })); return true; }
  catch { return false; }
}

const READING_KEY = "threatlens.feed.read.v1";
const kinds = ["news", "vulnerability", "ioc"] as const;
function safeIds(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && /^[A-Za-z0-9_.:-]{1,200}$/.test(v)).slice(-500) : [];
}
export function readFeedReading(): Set<string> {
  try {
    const raw = JSON.parse(localStorage.getItem(READING_KEY) ?? "null");
    const result = new Set<string>();
    for (const kind of kinds) {
      const legacy = kind === "news" ? "threatlens.feed.viewed" : kind === "ioc" ? "threatlens.feed.iocs.viewed" : "threatlens.feed.vulnerabilities.viewed";
      const values = raw?.version === 1 ? raw.ids?.[kind] : legacy ? JSON.parse(localStorage.getItem(legacy) ?? "[]") : [];
      for (const id of safeIds(values)) result.add(`${kind}:${id}`);
    }
    return result;
  } catch { return new Set(); }
}
export function markFeedRead(kind: typeof kinds[number], id: string) {
  try { markFeedReadMany(kind, [id]); } catch { /* Reading is optional browser-local state. */ }
}
export function markFeedReadMany(kind: typeof kinds[number], values: string[]) {
  if (!kinds.includes(kind) || values.length > 100 || values.some((id) => !/^[A-Za-z0-9_.:-]{1,200}$/.test(id))) throw new Error("Invalid reading selection.");
  const current = readFeedReading();
  let marked = 0;
  for (const id of new Set(values)) {
    const key = `${kind}:${id}`;
    if (!current.has(key)) marked++;
    current.delete(key); current.add(key);
  }
  const ids = Object.fromEntries(kinds.map((k) => [k, [...current].filter((v) => v.startsWith(`${k}:`)).map((v) => v.slice(k.length + 1)).slice(-500)]));
  try { localStorage.setItem(READING_KEY, JSON.stringify({ version: 1, ids })); }
  catch { throw new Error("Browser reading storage is unavailable. Reports are unchanged."); }
  window.dispatchEvent(new Event("threatlens:feed-reading"));
  return { marked, alreadyRead: new Set(values).size - marked };
}
export function relativeAge(value: string, now: number): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return "Not supplied";
  if (time > now + 60_000) return "Scheduled / future date";
  const minutes = Math.floor(Math.max(0, now - time) / 60_000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}
export function exactDate(value: string): string {
  if (!Number.isFinite(Date.parse(value))) return "Not supplied";
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "longOffset" }).format(new Date(value));
}
