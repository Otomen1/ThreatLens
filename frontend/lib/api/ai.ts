// AI explanation (downstream, optional).
//
// The AI layer explains a completed InvestigationSummary. It never influences
// findings, confidence, severity, priority, or recommendations. A non-"ok"
// status (disabled / unavailable / error) is a normal, expected response — not a
// failure — and the deterministic investigation always renders regardless.

import { post } from "./client";
import type { InvestigationSummary } from "./investigation";

export type AIStatus =
  | "ok"
  | "disabled"
  | "unavailable"
  | "timeout"
  | "invalid_response"
  | "error";

export interface FindingExplanation {
  finding_id: string;
  explanation: string;
}

export interface RecommendationExplanation {
  action: string;
  target_value: string;
  explanation: string;
}

export interface AIExplanation {
  status: AIStatus;
  provider: string;
  model: string | null;
  message: string;
  executive_summary: string;
  technical_summary: string;
  finding_explanations: FindingExplanation[];
  recommendation_explanations: RecommendationExplanation[];
  limitations: string[];
}

/**
 * Ask the AI layer to explain a completed investigation.
 *
 * Sends the deterministic {@link InvestigationSummary} (never raw provider data)
 * and returns an {@link AIExplanation}. The endpoint always responds 200; a
 * `disabled` / `unavailable` / `error` status is a normal result the caller
 * renders as a friendly note, not an exception.
 */
export function explain(
  summary: InvestigationSummary,
  signal?: AbortSignal,
): Promise<AIExplanation> {
  return post<AIExplanation>("/explain", summary, signal);
}
