import type { FeedRegion } from "./api/threatFeed";
import { NEWS_REGIONS, NEWS_TOPICS, newsHref, validNewsSource } from "./newsFeed";
import { iocTypes, vendors } from "./api/iocReports";

export const FEED_PRESETS_KEY = "threatlens.feed.presets.v1";
export const MAX_FEED_PRESETS = 10;
export type PresetView = "news" | "vulnerabilities" | "iocs";
export type FeedPresetDraft = { view: PresetView; region?: FeedRegion; filters: Record<string, string> };
export type FeedPreset = FeedPresetDraft & { id: string; name: string; saved_at: string };
const views = ["news", "vulnerabilities", "iocs"];
const hours = ["24", "168", "720"];

function cleanFilters(view: PresetView, region: FeedRegion | undefined, raw: Record<string, unknown>) {
  const result: Record<string, string> = { hours: hours.includes(String(raw.hours)) ? String(raw.hours) : "168" };
  const keep = (key: string, allowed: readonly string[]) => {
    const value = raw[key]; if (typeof value === "string" && allowed.includes(value)) result[key] = value;
  };
  if (view !== "news" || region) keep("sort", ["newest", "oldest"]);
  if (view === "news") {
    keep("topic", NEWS_TOPICS);
    if (typeof raw.source === "string" && validNewsSource(raw.source)) result.source = raw.source;
  } else if (view === "vulnerabilities") {
    keep("category", ["all", "new_cves", "zero_days", "known_exploited"]);
    keep("severity", ["critical", "high", "medium", "low"]);
    if (typeof raw.source === "string" && /^[A-Za-z0-9 ._&/()-]{1,150}$/.test(raw.source)) result.source = raw.source;
  } else {
    keep("vendor", Object.keys(vendors)); keep("kind", iocTypes); keep("view", ["indicators"]);
  }
  return result;
}

export function captureFeedPreset(view: PresetView, params: URLSearchParams, region?: FeedRegion): FeedPresetDraft {
  const selectedRegion = view === "news" && region && NEWS_REGIONS.includes(region) ? region : undefined;
  return { view, ...(selectedRegion ? { region: selectedRegion } : {}), filters: cleanFilters(view, selectedRegion, Object.fromEntries(params)) };
}

function cleanPreset(value: unknown): FeedPreset | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (!views.includes(String(record.view)) || typeof record.id !== "string" || !/^[A-Za-z0-9-]{1,80}$/.test(record.id)
    || typeof record.name !== "string" || !record.name.trim() || record.name.length > 60 || /[\u0000-\u001f\u007f]/.test(record.name)
    || typeof record.saved_at !== "string" || !Number.isFinite(Date.parse(record.saved_at))
    || !record.filters || typeof record.filters !== "object" || Array.isArray(record.filters)
    || (record.region !== undefined && (record.view !== "news" || !NEWS_REGIONS.includes(record.region as FeedRegion)))) return null;
  const view = record.view as PresetView, region = record.region as FeedRegion | undefined;
  return { id: record.id, name: record.name.trim(), saved_at: record.saved_at, view,
    ...(region ? { region } : {}), filters: cleanFilters(view, region, record.filters as Record<string, unknown>) };
}

export function readFeedPresets(): FeedPreset[] {
  try {
    const text = localStorage.getItem(FEED_PRESETS_KEY);
    if (!text || text.length > 32768) return [];
    const raw = JSON.parse(text);
    if (raw.version !== 1 || !Array.isArray(raw.items) || raw.items.length > MAX_FEED_PRESETS) return [];
    const items: FeedPreset[] = [], seen = new Set<string>();
    for (const entry of raw.items) {
      const item = cleanPreset(entry);
      if (item && !seen.has(item.id)) { seen.add(item.id); items.push(item); }
    }
    return items;
  } catch { return []; }
}

function write(items: FeedPreset[]) {
  try { localStorage.setItem(FEED_PRESETS_KEY, JSON.stringify({ version: 1, items })); }
  catch { throw new Error("Browser storage is unavailable. Filter presets were not changed."); }
  window.dispatchEvent(new Event("feed-presets"));
}

export function saveFeedPreset(name: string, draft: FeedPresetDraft): FeedPreset {
  const current = readFeedPresets();
  if (current.length >= MAX_FEED_PRESETS) throw new Error("The 10-preset limit is reached. Remove a preset first.");
  if (current.some((item) => item.name.toLowerCase() === name.trim().toLowerCase())) throw new Error("A preset with this name already exists. Choose another name.");
  const item = cleanPreset({ ...draft, id: crypto.randomUUID(), name: name.trim(), saved_at: new Date().toISOString() });
  if (!item) throw new Error("Use a preset name between 1 and 60 characters.");
  write([...current, item]); return item;
}

export function removeFeedPreset(id: string) {
  const current = readFeedPresets();
  if (current.some((item) => item.id === id)) write(current.filter((item) => item.id !== id));
}

export function feedPresetHref(value: FeedPresetDraft): string {
  // Rebuild from allowlisted fields; never navigate to a URL supplied by browser storage.
  const safe = captureFeedPreset(value.view, new URLSearchParams(value.filters), value.region);
  return safe.view === "news" ? newsHref(safe.region, new URLSearchParams(safe.filters))
    : `/threat-feed?${new URLSearchParams({ tab: safe.view, ...safe.filters })}`;
}
