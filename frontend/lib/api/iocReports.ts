import { get, getUncached } from "./client";

export type Ioc = { id: string; type: string; value: string; original: string; disposition: "source-reported"; verified: false };
export type IocReport = { targeting_evidence?: import('@/components/threat-feed/FeedFilters').TargetEvidence[]; id: string; vendor: string; title: string; path: string; source_url: string; article_url: string | null; published_at: string | null; activity_at: string; collected_at: string; commit: string; blob: string; parser_version: string; license: string; license_url: string; attribution: string; indicator_count: number; types: string[]; warnings: string[]; withdrawn: boolean };
export type IocSource = { vendor: string; name: string; url: string; enabled: boolean; license: string; status: string; last_success_at: string | null; pending: number; skipped: number; safe_error: string | null; next_attempt_at: string | null };
export type IocReportList = { items: IocReport[]; total: number; page: number; page_size: number; unique_indicators: number; recent_indicators: number; sources: IocSource[]; generated_at: string };
export type IocRow = Ioc & { vendors: string[]; reports: IocReport[]; activity_at: string };
export type IocIndicatorList = { items: IocRow[]; total: number; page: number; page_size: number };
export type IocDetail = { report: IocReport; indicators: Ioc[] };
export function getIocList(params: URLSearchParams, indicators: boolean, fresh = false, signal?: AbortSignal) {
  const path = `/threat-feed/${indicators ? "indicators" : "ioc-reports"}?${params}`;
  return fresh ? getUncached<IocReportList | IocIndicatorList>(path, signal) : get<IocReportList | IocIndicatorList>(path, signal);
}
export const getIocReport = (id: string, signal?: AbortSignal) => get<IocDetail>(`/threat-feed/ioc-reports/${encodeURIComponent(id)}`, signal);
export const getIocSources = () => get<IocSource[]>("/threat-feed/ioc-reports/sources");
export const vendors = { talos: "Cisco Talos", unit42: "Unit 42", eset: "ESET Research", sophoslabs: "SophosLabs" };
export const iocTypes = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"];
