// Operational health + the Operational Dashboard (read-only).
//
// `health`/`aiHealth` are lightweight, side-effect-free status endpoints used
// only for a passive system-status indicator. `systemHealth`/`systemUsage`/
// `systemConfig` back the Operational Dashboard itself — administrators/
// developers only, never rendered inside the Investigation Workspace. Every
// endpoint here is GET and side-effect-free: none can trigger an
// investigation, a detection generation, or an AI call.

import { get } from "./client";

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  uptime_seconds: number;
  started_at: string;
  timestamp: string;
}

export type AIHealthStatus = "disabled" | "ok" | "unavailable" | "error";

export interface AIHealth {
  status: AIHealthStatus;
  enabled: boolean;
  provider: string;
  model: string | null;
  reachable: boolean;
  model_available: boolean | null;
  detail: string | null;
  timestamp: string;
}

/** Liveness probe — resolves when the backend is up. */
export function health(signal?: AbortSignal): Promise<HealthStatus> {
  return get<HealthStatus>("/health", signal);
}

/** AI subsystem status (disabled / reachable / unavailable). */
export function aiHealth(signal?: AbortSignal): Promise<AIHealth> {
  return get<AIHealth>("/health/ai", signal);
}

export type ServiceState = "healthy" | "degraded" | "offline" | "disabled";

export interface ServiceStatus {
  name: string;
  display_name: string;
  status: ServiceState;
  detail: string;
}

export interface SystemHealthResponse {
  status: ServiceState;
  services: ServiceStatus[];
  timestamp: string;
}

export interface ProviderUsage {
  name: string;
  display_name: string;
  configured: boolean;
  enabled: boolean;
  requests: number;
  successful: number;
  failed: number;
  success_rate: number | null;
  avg_latency_ms: number | null;
  last_request_at: string | null;
  rate_limit_remaining: number | null;
  cache_hits: number;
  cache_misses: number;
}

export interface KnowledgeProviderUsage {
  name: string;
  display_name: string;
  queries: number;
  successful: number;
  failed: number;
  avg_latency_ms: number | null;
  cache_hits: number;
  cache_misses: number;
}

export interface AIUsage {
  provider: string;
  model: string | null;
  enabled: boolean;
  connected: boolean;
  requests: number;
  successful: number;
  failed: number;
  avg_response_ms: number | null;
  fastest_response_ms: number | null;
  slowest_response_ms: number | null;
  avg_prompt_chars: number | null;
  avg_completion_chars: number | null;
  estimated_tokens: number | null;
  estimated_cost_usd: number | null;
}

export interface DetectionEngineeringUsage {
  generated_total: number;
  by_language: Record<string, number>;
  avg_generation_ms: number | null;
  last_generated_at: string | null;
}

export interface DetectionKnowledgeUsage {
  library_version: string;
  rules_indexed: number;
  repositories: number;
  sync_status: string;
  last_synchronized_at: string | null;
  cache_size_bytes: number | null;
  queries: number;
  avg_query_latency_ms: number | null;
}

export interface InvestigationUsage {
  executed: number;
  avg_duration_ms: number | null;
  avg_findings: number | null;
  avg_recommendations: number | null;
  avg_confidence: number | null;
  avg_ai_response_ms: number | null;
}

export interface UsageResponse {
  threat_intelligence: ProviderUsage[];
  knowledge: KnowledgeProviderUsage[];
  ai: AIUsage;
  detection_engineering: DetectionEngineeringUsage;
  detection_knowledge: DetectionKnowledgeUsage;
  investigations: InvestigationUsage;
  timestamp: string;
}

export interface ConfigItem {
  name: string;
  display_name: string;
  configured: boolean;
  enabled: boolean;
}

export interface AIConfigStatus {
  provider: string;
  enabled: boolean;
  model: string | null;
}

export interface ConfigStatusResponse {
  threat_intelligence: ConfigItem[];
  knowledge: ConfigItem[];
  ai: AIConfigStatus;
  timestamp: string;
}

/** Section 1 — per-service Healthy/Degraded/Offline/Disabled + an overall rollup. */
export function systemHealth(signal?: AbortSignal): Promise<SystemHealthResponse> {
  return get<SystemHealthResponse>("/system/health", signal);
}

/** Section 2 — incremental request/latency counters. Never includes a secret. */
export function systemUsage(signal?: AbortSignal): Promise<UsageResponse> {
  return get<UsageResponse>("/system/usage", signal);
}

/** Section 3 — configured/enabled booleans only. Never includes a credential. */
export function systemConfig(signal?: AbortSignal): Promise<ConfigStatusResponse> {
  return get<ConfigStatusResponse>("/system/config", signal);
}
