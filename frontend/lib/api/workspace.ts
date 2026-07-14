// Investigation Workspace (Phase 8.0) — a persistence layer over completed
// investigations. Not a new intelligence engine: this module only stores and
// retrieves what /investigate, /detections, and (in a future phase)
// /correlation already produced.

import { del, get, post, put } from "./client";
import type { DetectionPackage } from "./detection";
import type { EntityType, InvestigationSummary } from "./investigation";

export type WorkspaceStatus = "open" | "in_progress" | "closed" | "archived";

/**
 * Mirrors `threatlens.correlation.models.CorrelationSummary` by name only. No
 * UI renders its fields yet — Correlation isn't wired into `/investigate`, so
 * this is almost always absent on a saved investigation. Kept deliberately
 * opaque until a future phase gives it a real consumer and a precise shape.
 */
export type CorrelationSummary = Record<string, unknown>;

export interface WorkspaceInvestigation {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  status: WorkspaceStatus;
  tags: string[];
  summary: string | null;
  severity: number | null;
  investigation_type: EntityType;
  investigation_summary: InvestigationSummary | null;
  detection_package: DetectionPackage | null;
  correlation_summary: CorrelationSummary | null;
}

/** One row of `GET /workspace` — metadata only, no nested engine outputs. */
export interface WorkspaceListItem {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  status: WorkspaceStatus;
  tags: string[];
  summary: string | null;
  severity: number | null;
  investigation_type: EntityType;
}

export interface WorkspaceListResponse {
  investigations: WorkspaceListItem[];
  total: number;
}

export interface SaveInvestigationRequest {
  title: string;
  status?: WorkspaceStatus;
  tags?: string[];
  summary?: string | null;
  severity?: number | null;
  investigation_type: EntityType;
  investigation_summary?: InvestigationSummary | null;
  detection_package?: DetectionPackage | null;
  correlation_summary?: CorrelationSummary | null;
}

/** Every field is optional; an omitted field leaves the saved value unchanged. */
export interface UpdateInvestigationRequest {
  title?: string;
  status?: WorkspaceStatus;
  tags?: string[];
  summary?: string | null;
  severity?: number | null;
  investigation_type?: EntityType;
  investigation_summary?: InvestigationSummary | null;
  detection_package?: DetectionPackage | null;
  correlation_summary?: CorrelationSummary | null;
}

export interface WorkspaceListFilters {
  status?: WorkspaceStatus;
  severity?: number;
  investigation_type?: EntityType;
  tag?: string;
  q?: string;
}

function buildQuery(filters: WorkspaceListFilters): string {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.severity !== undefined) params.set("severity", String(filters.severity));
  if (filters.investigation_type) params.set("investigation_type", filters.investigation_type);
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.q) params.set("q", filters.q);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/** Save a completed investigation. Attaches whatever engine outputs the caller already has. */
export function saveInvestigation(
  request: SaveInvestigationRequest,
  signal?: AbortSignal,
): Promise<WorkspaceInvestigation> {
  return post<WorkspaceInvestigation>("/workspace", request, signal);
}

/** List saved investigations (metadata only), optionally filtered; most recently updated first. */
export function listInvestigations(
  filters: WorkspaceListFilters = {},
  signal?: AbortSignal,
): Promise<WorkspaceListResponse> {
  return get<WorkspaceListResponse>(`/workspace${buildQuery(filters)}`, signal);
}

/** Load one saved investigation, including every attached engine output. */
export function getInvestigation(
  id: string,
  signal?: AbortSignal,
): Promise<WorkspaceInvestigation> {
  return get<WorkspaceInvestigation>(`/workspace/${encodeURIComponent(id)}`, signal);
}

/** Partially update a saved investigation's metadata (and/or re-attach an output). */
export function updateInvestigation(
  id: string,
  request: UpdateInvestigationRequest,
  signal?: AbortSignal,
): Promise<WorkspaceInvestigation> {
  return put<WorkspaceInvestigation>(`/workspace/${encodeURIComponent(id)}`, request, signal);
}

/** Delete a saved investigation. */
export function deleteInvestigation(id: string, signal?: AbortSignal): Promise<void> {
  return del(`/workspace/${encodeURIComponent(id)}`, signal);
}

// --- Investigation Timeline (Phase 8.1) ---
//
// A read-only, derived view over a saved investigation's existing evidence —
// never a new intelligence engine. An event exists only when the evidence it
// came from already carried an explicit timestamp; the UI renders exactly
// what the backend returns and never re-sorts, re-derives, or estimates a
// missing time itself.

/**
 * `event_type`/`source_type` are left as plain `string` rather than exact
 * unions — mirrors `Evidence.type` in `./investigation`, which does the same
 * for the same reason: nothing in the UI branches on a specific value.
 */
export interface TimelineEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  source_type: string;
  source_id: string;
  severity: number | null;
  evidence_references: string[];
}

export interface Timeline {
  investigation_id: string;
  entity_type: EntityType;
  entity_value: string;
  generated_at: string;
  events: TimelineEvent[];
}

/** Derive the read-only timeline for one saved investigation. */
export function getInvestigationTimeline(
  id: string,
  signal?: AbortSignal,
): Promise<Timeline> {
  return get<Timeline>(`/workspace/${encodeURIComponent(id)}/timeline`, signal);
}

// --- Evidence Relationship Graph (Phase 8.2) ---
//
// A read-only, derived view over a saved investigation's existing evidence
// and correlation output — never a new intelligence engine. A node or edge
// exists only when the backend found supporting evidence or an explicit
// relationship; the UI renders exactly what it returns and never infers,
// merges, or lays out a connection itself.

/**
 * `node_type`/`relationship_type` are left as plain `string` rather than
 * exact unions — mirrors `TimelineEvent.event_type` above for the same
 * reason: the underlying vocabularies genuinely differ by source, and
 * nothing in the UI branches on a specific value.
 */
export interface GraphNode {
  node_id: string;
  node_type: string;
  label: string;
  value: string;
  severity: number | null;
  source_references: string[];
  metadata: Record<string, unknown>;
}

export interface GraphEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  explanation: string;
  evidence_references: string[];
  source_references: string[];
}

export interface EvidenceGraph {
  investigation_id: string;
  entity_type: EntityType;
  entity_value: string;
  generated_at: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
  graph_version: string;
}

/** Derive the read-only evidence relationship graph for one saved investigation. */
export function getInvestigationGraph(
  id: string,
  signal?: AbortSignal,
): Promise<EvidenceGraph> {
  return get<EvidenceGraph>(`/workspace/${encodeURIComponent(id)}/graph`, signal);
}
