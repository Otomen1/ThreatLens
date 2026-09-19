import { get, post } from "./client";
import type { EntityType } from "./investigation";

export interface IdentityProviderState {
  name: string;
  display_name: string;
  enabled: boolean;
  configured: boolean;
  status: "operational" | "degraded" | "unavailable" | "disabled" | "unknown";
  detail: string | null;
}

export interface IdentityEvidence {
  type: string;
  summary: string;
  value: string | null;
  observed_at: string | null;
  data: Record<string, unknown>;
}

export interface IdentityFinding {
  provider: string;
  provider_display_name: string | null;
  status: string;
  error: { message: string; retryable: boolean; detail: string | null } | null;
  summary: string;
  evidence: IdentityEvidence[];
  fetched_at: string | null;
}

export interface IdentitySummary {
  entity_type: EntityType;
  entity_value: string;
  findings: IdentityFinding[];
  statistics: {
    providers_queried: number;
    providers_ok: number;
    total_findings: number;
    total_assets: number;
    categories: string[];
  };
  metadata: { generated_at: string; framework_version: string };
}

export interface IdentityFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  providers_registered: number;
  enabled: boolean;
  providers: IdentityProviderState[];
  summary: IdentitySummary | null;
}

export function identityFrameworkStatus(signal?: AbortSignal): Promise<IdentityFrameworkStatus> {
  return get<IdentityFrameworkStatus>("/identity", signal);
}

export interface IdentityEmailCheckResponse {
  summary: IdentitySummary;
  cache_status: "hit" | "miss" | "refreshed" | "disabled";
  checked_at: string;
}

export interface PasswordRangeResponse {
  prefix: string;
  suffixes: Array<{ suffix: string; count: number }>;
  checked_at: string;
}

export function checkIdentityEmail(
  email: string,
  refresh = false,
  signal?: AbortSignal,
): Promise<IdentityEmailCheckResponse> {
  return post<IdentityEmailCheckResponse>("/identity/email/check", { email, refresh }, signal);
}

export function passwordHashRange(prefix: string, signal?: AbortSignal): Promise<PasswordRangeResponse> {
  return get<PasswordRangeResponse>(`/identity/password-range/${encodeURIComponent(prefix)}`, signal);
}
