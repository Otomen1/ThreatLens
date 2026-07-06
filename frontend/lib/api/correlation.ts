// Investigation Correlation Engine (Phase 7.0 — framework only).
//
// A pure, deterministic engine that combines a completed investigation's
// existing findings into higher-level correlation observations. It never
// invents evidence and never scores. This is a pure readiness probe: no
// correlation is run, not integrated into /investigate yet.

import { get } from "./client";

export interface CorrelationFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  rules_registered: number;
}

/** Fetch Investigation Correlation Engine readiness (Phase 7.0 — seed rules only). */
export function correlationFrameworkStatus(
  signal?: AbortSignal,
): Promise<CorrelationFrameworkStatus> {
  return get<CorrelationFrameworkStatus>("/correlation", signal);
}
