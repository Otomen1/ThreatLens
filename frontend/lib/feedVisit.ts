import type { FeedActivity, FeedActivityKind } from "./api/threatFeed";
import { bookmarkPath } from "./feedBookmarks";

export const FEED_VISIT_KEY = "threatlens.feed.visit.v1";
export const FEED_VISIT_SESSION_KEY = "threatlens.feed.visit-session.v1";
export const FEED_VISIT_SESSION_MS = 30 * 60 * 1000;
export type FeedVisit = { baseline: string | null; opened_at: number };
export const ACTIVITY_KINDS: FeedActivityKind[] = ["news", "vulnerability", "ioc"];

function timestamp(value: unknown, now: number): value is string {
  return typeof value === "string" && value.length <= 40 && /(?:Z|[+-]\d{2}:\d{2})$/i.test(value)
    && Number.isFinite(Date.parse(value)) && Date.parse(value) <= now + 60_000;
}
function previousVisit(now: number): string | null {
  try {
    const text = localStorage.getItem(FEED_VISIT_KEY);
    const raw = text && text.length <= 512 ? JSON.parse(text) : null;
    return raw?.version === 1 && timestamp(raw.checked_at, now) ? raw.checked_at : null;
  } catch { return null; }
}
export function startFeedVisit(now = Date.now()): FeedVisit {
  try {
    const text = sessionStorage.getItem(FEED_VISIT_SESSION_KEY);
    const raw = text && text.length <= 512 ? JSON.parse(text) : null;
    if (raw?.version === 1 && Number.isFinite(raw.opened_at) && raw.opened_at <= now
      && now - raw.opened_at < FEED_VISIT_SESSION_MS && (raw.baseline === null || timestamp(raw.baseline, now))) {
      return { baseline: raw.baseline, opened_at: raw.opened_at };
    }
  } catch { /* The brief still works for this mounted view. */ }
  const visit = { baseline: previousVisit(now), opened_at: now };
  try { sessionStorage.setItem(FEED_VISIT_SESSION_KEY, JSON.stringify({ version: 1, ...visit })); } catch { /* Optional visit continuity. */ }
  return visit;
}

export function finishFeedVisit(visit: FeedVisit, checked_at: string, caughtUp = false, now = Date.now()) {
  if (!timestamp(checked_at, now)) throw new Error("Invalid brief timestamp.");
  const next = { ...visit, baseline: caughtUp || !visit.baseline ? checked_at : visit.baseline };
  let persisted = true;
  try {
    // A slower tab must not move the shared last-successful-visit clock backwards.
    const previous = previousVisit(now);
    if (!previous || Date.parse(previous) < Date.parse(checked_at)) localStorage.setItem(FEED_VISIT_KEY, JSON.stringify({ version: 1, checked_at }));
  } catch { persisted = false; }
  try { sessionStorage.setItem(FEED_VISIT_SESSION_KEY, JSON.stringify({ version: 1, ...next })); } catch { persisted = false; }
  return { visit: next, persisted };
}

export function isFeedActivity(value: unknown, now = Date.now()): value is FeedActivity {
  if (!value || typeof value !== "object") return false;
  const record = value as FeedActivity;
  if (!timestamp(record.generated_at, now) || !timestamp(record.window_start, now)
    || (record.since !== null && !timestamp(record.since, now)) || typeof record.limited !== "boolean" || !record.groups) return false;
  const start = Date.parse(record.window_start), end = Date.parse(record.generated_at);
  return start <= end && ACTIVITY_KINDS.every((kind) => {
    const group = record.groups[kind];
    return group && Number.isSafeInteger(group.total) && group.total >= 0 && Array.isArray(group.items)
      && group.items.length <= Math.min(3, group.total) && group.items.every((item) => item && item.kind === kind
        && typeof item.id === "string" && /^[A-Za-z0-9_.:-]{1,200}$/.test(item.id)
        && typeof item.title === "string" && item.title.length <= 500 && typeof item.source === "string" && item.source.length <= 2000
        && timestamp(item.activity_at, now) && Date.parse(item.activity_at) > start && Date.parse(item.activity_at) <= end
        && item.href === bookmarkPath(kind, item.id));
  });
}
