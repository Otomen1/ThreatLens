import { get, post } from "./client";

export type FeedRegion = "global" | "malaysia" | "southeast_asia";
export type FeedEntity = { type: string; value: string; normalized_value: string; disposition: string; verified: boolean };
export type FeedItem = { id: string; source_id: string; source_name: string; source_kind: string; title: string; excerpt: string; summary: string; url: string; published_at: string; region: FeedRegion; relevance: string; region_reasons: string[]; topic: string; severity: string | null; entities: FeedEntity[] };
export type FeedList = { items: FeedItem[]; total: number; page: number; page_size: number };
export type FeedSummary = { regions: Record<FeedRegion, { total: number; recent: number }>; critical: number; new_iocs: number; last_refreshed_at: string | null; next_refresh_at: string | null; source_errors: number };
export type FeedSource = { id: string; name: string; kind: string; enabled: boolean; last_success_at: string | null; last_error_code: string | null; last_error: string | null; last_added: number };
export type FeedRefresh = { status: string; items_added: number; sources_succeeded: number; sources_attempted: number; next_refresh_at: string | null };

export const getFeedSummary = () => get<FeedSummary>("/threat-feed/summary");
export const getFeedItem = (id: string) => get<FeedItem>(`/threat-feed/items/${encodeURIComponent(id)}`);
export const getFeedSources = () => get<FeedSource[]>("/threat-feed/sources");
export const refreshFeed = () => post<FeedRefresh>("/threat-feed/refresh", {});
export function getFeedItems(params: Record<string, string | number | undefined>) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => { if (value !== undefined && value !== "") query.set(key, String(value)); });
  return get<FeedList>(`/threat-feed/items?${query.toString()}`);
}
