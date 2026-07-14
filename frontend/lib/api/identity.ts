// Identity Intelligence (Phase 6.0 — framework only, no providers yet).
//
// Answers "what is known about this identity" (breaches, credential exposure,
// directory profile, …), never "is it malicious" or "where is it exposed"
// (those remain Threat and Exposure Intelligence's questions — separate
// frameworks). This is a pure readiness probe: no entity lookup, not
// integrated into /investigate.

import { get } from "./client";

export interface IdentityFrameworkStatus {
  status: string;
  message: string;
  framework_version: string;
  providers_registered: number;
}

/** Fetch Identity Intelligence Framework readiness (Phase 6.0 — no providers yet). */
export function identityFrameworkStatus(signal?: AbortSignal): Promise<IdentityFrameworkStatus> {
  return get<IdentityFrameworkStatus>("/identity", signal);
}
