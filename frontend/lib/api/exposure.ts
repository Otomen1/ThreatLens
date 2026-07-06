// Exposure Intelligence (Phase 5.1 — Shodan is the first provider).
//
// Answers "where is this entity exposed", never "is it malicious" (that
// remains Threat Intelligence's question — a separate framework). Not
// integrated into /investigate: a dedicated, isolated lookup.

import { get } from "./client";
import type { EntityType } from "./investigation";

export type ExposureProviderHealthStatus =
  | "unknown"
  | "operational"
  | "degraded"
  | "unavailable"
  | "disabled";

export interface ExposureProviderStatusInfo {
  name: string;
  display_name: string;
  status: ExposureProviderHealthStatus;
  detail: string | null;
}

export type ExposureResultStatus =
  | "ok"
  | "not_found"
  | "unsupported"
  | "error"
  | "timeout"
  | "rate_limited"
  | "unauthorized";

export type ExposureCapability =
  | "open_ports"
  | "certificates"
  | "passive_dns"
  | "hosting"
  | "asn"
  | "services"
  | "subdomains"
  | "dns_history"
  | "breaches"
  | "credential_exposure"
  | "pastes"
  | "internet_noise";

export interface ExposureFindingErrorInfo {
  message: string;
  retryable: boolean;
  detail: string | null;
}

export interface ExposureEvidence {
  type: string;
  summary: string;
  value: string | null;
  observed_at: string | null;
  data: Record<string, unknown>;
}

export interface ExposureAsset {
  asset_type: string;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  attributes: Record<string, unknown>;
}

export interface ExposureReference {
  title: string;
  url: string;
  description: string | null;
}

export interface ExposureFinding {
  provider: string;
  provider_display_name: string | null;
  entity_type: EntityType;
  entity_value: string;
  status: ExposureResultStatus;
  error: ExposureFindingErrorInfo | null;
  category: ExposureCapability | null;
  summary: string;
  evidence: ExposureEvidence[];
  assets: ExposureAsset[];
  references: ExposureReference[];
  fetched_at: string | null;
}

export interface ExposureStatistics {
  providers_queried: number;
  providers_ok: number;
  total_findings: number;
  total_assets: number;
  categories: ExposureCapability[];
}

export interface ExposureMetadata {
  entity_type: EntityType;
  entity_value: string;
  generated_at: string;
  framework_version: string;
}

export interface ExposureSummary {
  entity_type: EntityType;
  entity_value: string;
  findings: ExposureFinding[];
  references: ExposureReference[];
  statistics: ExposureStatistics;
  metadata: ExposureMetadata;
}

export interface ExposureFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  providers_registered: number;
  providers: ExposureProviderStatusInfo[];
  summary: ExposureSummary | null;
}

/**
 * Fetch Exposure Intelligence Framework + provider status, optionally running
 * a real lookup when `value` is given (e.g. an IP). A disabled or
 * unconfigured provider still returns 200 with a well-formed empty/failed
 * summary — never an error.
 */
export function exposureFrameworkStatus(
  value?: string,
  signal?: AbortSignal,
): Promise<ExposureFrameworkStatus> {
  const trimmed = value?.trim();
  const query = trimmed ? `?value=${encodeURIComponent(trimmed)}` : "";
  return get<ExposureFrameworkStatus>(`/exposure${query}`, signal);
}
