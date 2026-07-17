// Case Management (Phase 9.0) — an operational layer *above* the Workspace
// platform. A Case organizes zero or more saved investigations by reference
// (id only); it never duplicates investigation content. This module only
// transports requests and types responses — nothing here recomputes or
// re-derives anything a Workspace investigation already carries.

import { del, delWithBody, get, patch, post } from "./client";

export type CaseStatus = "open" | "in_progress" | "resolved" | "closed";
export type CasePriority = "low" | "medium" | "high" | "critical";

export interface CaseNote {
  author: string;
  timestamp: string;
  content: string;
}

export interface Case {
  id: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  priority: CasePriority;
  created_at: string;
  updated_at: string;
  owner: string | null;
  tags: string[];
  linked_workspace_ids: string[];
  notes: CaseNote[];
  metadata: Record<string, unknown>;
}

export interface CreateCaseRequest {
  title: string;
  description?: string | null;
  status?: CaseStatus;
  priority?: CasePriority;
  owner?: string | null;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

/** Every field is optional; an omitted field leaves the saved value unchanged. */
export interface UpdateCaseRequest {
  title?: string;
  description?: string | null;
  status?: CaseStatus;
  priority?: CasePriority;
  owner?: string | null;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface CaseListFilters {
  status?: CaseStatus;
  priority?: CasePriority;
  tag?: string;
  owner?: string;
  title?: string;
}

export interface CaseListResponse {
  cases: Case[];
  total: number;
}

function buildQuery(filters: CaseListFilters): string {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.priority) params.set("priority", filters.priority);
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.owner) params.set("owner", filters.owner);
  if (filters.title) params.set("title", filters.title);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/** Create a new case. */
export function createCase(request: CreateCaseRequest, signal?: AbortSignal): Promise<Case> {
  return post<Case>("/cases", request, signal);
}

/** List cases (full records), optionally filtered; most recently updated first. */
export function listCases(
  filters: CaseListFilters = {},
  signal?: AbortSignal,
): Promise<CaseListResponse> {
  return get<CaseListResponse>(`/cases${buildQuery(filters)}`, signal);
}

/** Load one case. */
export function getCase(id: string, signal?: AbortSignal): Promise<Case> {
  return get<Case>(`/cases/${encodeURIComponent(id)}`, signal);
}

/** Partially update a case's metadata and/or transition its status. */
export function updateCase(
  id: string,
  request: UpdateCaseRequest,
  signal?: AbortSignal,
): Promise<Case> {
  return patch<Case>(`/cases/${encodeURIComponent(id)}`, request, signal);
}

/** Delete a case. Never touches any linked Workspace investigation. */
export function deleteCase(id: string, signal?: AbortSignal): Promise<void> {
  return del(`/cases/${encodeURIComponent(id)}`, signal);
}

/** Link one Workspace investigation to a case. Idempotent. */
export function linkWorkspaceToCase(
  id: string,
  workspaceId: string,
  signal?: AbortSignal,
): Promise<Case> {
  return post<Case>(
    `/cases/${encodeURIComponent(id)}/workspace`,
    { workspace_id: workspaceId },
    signal,
  );
}

/** Unlink one Workspace investigation from a case. Idempotent. */
export function unlinkWorkspaceFromCase(
  id: string,
  workspaceId: string,
  signal?: AbortSignal,
): Promise<Case> {
  return delWithBody<Case>(
    `/cases/${encodeURIComponent(id)}/workspace/${encodeURIComponent(workspaceId)}`,
    signal,
  );
}

/** Append one analyst note to a case. Notes are never edited or removed. */
export function addCaseNote(
  id: string,
  author: string,
  content: string,
  signal?: AbortSignal,
): Promise<Case> {
  return post<Case>(`/cases/${encodeURIComponent(id)}/notes`, { author, content }, signal);
}
