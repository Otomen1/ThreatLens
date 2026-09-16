import type { InvestigationResponse } from "./api";

export function providerCounts(investigation: InvestigationResponse) {
  const providers = investigation.threat_intelligence.providers;
  return {
    successful: providers.filter((provider) => provider.status === "ok").length,
    failed: providers.filter((provider) => ["error", "timeout", "rate_limited", "unauthorized"].includes(provider.status)).length,
  };
}

export function riskLabel(posture: number): string {
  return ["Unknown", "Low", "Medium", "High", "Critical"][posture] ?? "Unknown";
}

export function detectionEligible(investigation: InvestigationResponse): boolean {
  return investigation.investigation_summary.findings.length > 0;
}

export function detectionEligibility(investigation: InvestigationResponse): { eligible: boolean; reason: string; formats: number } {
  const findings = investigation.investigation_summary.findings;
  const observable = new Set(["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]);
  const supported = findings.filter((finding) => observable.has(finding.subject_type) && finding.severity > 0);
  if (supported.length === 0) return { eligible: false, reason: findings.length ? "Findings are not log-observable or actionable." : "No findings support rule generation.", formats: 0 };
  return { eligible: true, reason: `${supported.length} finding${supported.length === 1 ? "" : "s"} support deterministic IOC rules.`, formats: 8 };
}

function csvCell(value: unknown): string {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function rowsToCsv(rows: Array<{
  value: string; type: string; state: string; posture?: number; confidence?: number;
  findings?: number; successfulProviders?: number; failedProviders?: number;
  conflict?: boolean; errorCode?: string | null;
}>): string {
  const header = ["value", "type", "state", "posture", "confidence", "findings", "successful_providers", "failed_providers", "conflict", "error_code"];
  return [header, ...rows.map((row) => [row.value, row.type, row.state, row.posture, row.confidence, row.findings, row.successfulProviders, row.failedProviders, row.conflict, row.errorCode])]
    .map((line) => line.map(csvCell).join(","))
    .join("\n");
}

export function downloadText(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
