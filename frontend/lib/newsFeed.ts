import type { FeedHomeResponse, FeedItem, FeedRegion } from "./api/threatFeed";

export const NEWS_REGIONS: FeedRegion[] = ["global", "southeast_asia", "malaysia"];
export const NEWS_REGION_DETAILS: Record<FeedRegion, { label: string; icon: string; slug: string }> = {
  global: { label: "Global", icon: "◎", slug: "global" },
  southeast_asia: { label: "Southeast Asia", icon: "◫", slug: "southeast-asia" },
  malaysia: { label: "Malaysia", icon: "🇲🇾", slug: "malaysia" },
};
export const NEWS_TOPICS = ["advisory", "vulnerability", "active_exploitation", "phishing", "ransomware", "malware", "breach", "supply_chain", "threat_actor", "scam", "research"];
export const NEWS_PAGE_SIZE = 10;
export function isNewsItem(value: unknown): value is FeedItem {
  if (!value || typeof value !== "object") return false;
  const item = value as FeedItem;
  return typeof item.id === "string" && typeof item.title === "string" && typeof item.source_name === "string"
    && typeof item.published_at === "string" && Number.isFinite(Date.parse(item.published_at))
    && NEWS_REGIONS.includes(item.region) && typeof item.topic === "string"
    && (item.severity === null || typeof item.severity === "string")
    && (item.targeting_evidence === undefined || (Array.isArray(item.targeting_evidence) && item.targeting_evidence.every((evidence) => evidence
      && typeof evidence.region === "string" && typeof evidence.source === "string" && typeof evidence.field === "string"
      && typeof evidence.excerpt === "string" && typeof evidence.related_report === "boolean")));
}
export function newsRegionFromSlug(slug: string): FeedRegion | undefined {
  return NEWS_REGIONS.find((region) => NEWS_REGION_DETAILS[region].slug === slug);
}
export function newsPath(region?: FeedRegion): string {
  return region ? `/threat-feed/news/${NEWS_REGION_DETAILS[region].slug}` : "/threat-feed";
}
export function newsHref(region: FeedRegion | undefined, params: URLSearchParams, keepPage = false): string {
  const next = new URLSearchParams();
  for (const key of ["query", "topic", "hours", ...(region ? ["sort"] : []), ...(keepPage && region ? ["page"] : [])]) {
    const value = params.get(key);
    if (value) next.set(key, value);
  }
  const suffix = next.toString();
  return `${newsPath(region)}${suffix ? `?${suffix}` : ""}`;
}
export function latestNews(response: FeedHomeResponse): FeedItem[] {
  const unique = new Map<string, FeedItem>();
  for (const region of NEWS_REGIONS) {
    for (const item of response.sections[region].items) if (!unique.has(item.id)) unique.set(item.id, item);
  }
  return [...unique.values()].sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at) || b.id.localeCompare(a.id)).slice(0, NEWS_PAGE_SIZE);
}
export function isNewsListPath(path: string): boolean {
  return NEWS_REGIONS.some((region) => path === newsPath(region));
}
