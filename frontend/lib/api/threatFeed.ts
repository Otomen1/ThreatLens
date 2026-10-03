import { get, getUncached, post } from "./client";
import type { TargetEvidence } from "@/components/threat-feed/FeedFilters";

export type FeedRegion = "global" | "malaysia" | "southeast_asia";
export type FeedEntity = { type: string; value: string; normalized_value: string; disposition: string; verified: boolean };
export type FeedItem = { targeting_evidence?: TargetEvidence[]; id: string; source_id: string; source_name: string; source_kind: string; title: string; excerpt: string; summary: string; url: string; published_at: string; region: FeedRegion; relevance: string; region_reasons: string[]; topic: string; severity: string | null; entities: FeedEntity[] };
export type FeedList = { items: FeedItem[]; total: number; page: number; page_size: number };
export type FeedSummary = { regions: Record<FeedRegion, { total: number; recent: number }>; critical: number; new_iocs: number; last_refreshed_at: string | null; next_refresh_at: string | null; source_errors: number };
export type FeedSource = { id: string; name: string; kind: string; enabled: boolean; last_success_at: string | null; last_error_code: string | null; last_error: string | null; last_added: number };
export type FeedRefresh = { status: string; items_added: number; sources_succeeded: number; sources_attempted: number; next_refresh_at: string | null };
export type FeedHomeSection = { items: FeedItem[]; total: number };
export type FeedHomeResponse = { summary: FeedSummary; sections: Record<FeedRegion, FeedHomeSection>; generated_at: string };
export type FeedHomeParams = { query?: string; topic?: string; hours?: number; limit_per_region?: number; sort?: string };

export type Vulnerability = {
  targeting_evidence?: TargetEvidence[];
  id: string; cve_id: string | null; title: string; description: string;
  published_at: string | null; activity_at: string; updated_at: string;
  products: string[]; severity: string | null; sources: string[]; references: string[];
  scores: { source: string; version: string; score: number; severity: string | null }[];
  reports: { id: string; title: string; url: string; source_id: string; source_name: string; published_at: string; excerpt: string; zero_day: boolean }[];
  reported_zero_day: boolean; known_exploited: boolean; kev_added_at: string | null;
};
export type VulnerabilityList = {
  items: Vulnerability[]; total: number; page: number; page_size: number;
  published_24h: number; zero_days_24h: number; kev_added_24h: number;
  sources: string[]; last_synced_at: string | null; sync_status: string; generated_at: string;
};
export function getVulnerabilities(params: URLSearchParams, fresh = false, signal?: AbortSignal) {
  const path = `/threat-feed/vulnerabilities?${params}`;
  return fresh ? getUncached<VulnerabilityList>(path, signal) : get<VulnerabilityList>(path, signal);
}
export const getVulnerability = (id: string) => get<Vulnerability>(`/threat-feed/vulnerabilities/${encodeURIComponent(id)}`);

export const getFeedSummary = () => get<FeedSummary>("/threat-feed/summary");
export const getFeedItem = (id: string) => get<FeedItem>(`/threat-feed/items/${encodeURIComponent(id)}`);
export const getFeedSources = () => get<FeedSource[]>("/threat-feed/sources");
export const refreshFeed = async () => {
  const result = await post<FeedRefresh>("/threat-feed/refresh", {});
  window.dispatchEvent(new Event("threat-feed-refreshed"));
  return result;
};
export function getFeedHome(params: FeedHomeParams, options?: { fresh?: boolean; signal?: AbortSignal }) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => { if (value !== undefined && value !== "") query.set(key, String(value)); });
  const path = `/threat-feed/home?${query.toString()}`;
  return options?.fresh ? getUncached<FeedHomeResponse>(path, options.signal) : get<FeedHomeResponse>(path, options?.signal);
}
export function getFeedItems(params: Record<string, string | number | undefined>) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => { if (value !== undefined && value !== "") query.set(key, String(value)); });
  return get<FeedList>(`/threat-feed/items?${query.toString()}`);
}
