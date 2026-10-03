import { post } from "./client";

export type PocSource = "metasploit" | "nuclei";
export type PocResource = {
  source: PocSource; id: string; name: string; path: string; kind: "exploit" | "auxiliary" | "detection" | "other";
  module_type: string | null; description: string; cves: string[]; platforms: string[];
  disclosure_date: string | null; modified_at: string | null; check_supported: boolean | null;
  severity: string | null; url: string; verification: "cve_reference_confirmed"; locally_tested: false;
};
export type PocSourceResult = {
  source: PocSource; cve: string; status: "completed" | "no_matches" | "timed_out" | "rate_limited" | "busy" | "unavailable";
  matches: PocResource[]; total_matches: number; truncated: boolean; checked_at: string;
  cache_age_seconds: number | null; cached: boolean; stale: boolean; error_code: string | null;
  message: string | null; retryable: boolean; next_eligible_at: string | null; skipped_records: number;
};
export const lookupPoc = (source: PocSource, cve: string, refresh: boolean, signal: AbortSignal) =>
  post<PocSourceResult>(`/poc/lookup/${source}`, { cve, refresh }, signal);

export function normalizePocCve(value: string): string | null {
  const cve = value.trim().toUpperCase();
  return /^CVE-[0-9]{4}-[0-9]{4,20}$/.test(cve) && cve.length <= 32 ? cve : null;
}
