// Intelligence Collections (Phase 9.1) — reusable, analyst-curated sets of
// threat intelligence (indicators) that may reference zero or more Workspace
// investigations and zero or more Cases by id. Collections are NOT
// analytical engines, NOT Cases, and NOT Workspaces — this module only
// transports requests and types responses; nothing here classifies,
// enriches, deduplicates, or normalizes — that's all server-side (see
// backend/src/threatlens/collections/).

import { del, delWithPayload, get, patch, post } from "./client";

export type IndicatorType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "hostname"
  | "url"
  | "email"
  | "sha1"
  | "sha256"
  | "md5"
  | "cve"
  | "mitre_technique"
  | "mitre_software"
  | "mitre_group"
  | "registry"
  | "mutex"
  | "filename"
  | "process"
  | "certificate";

export type CollectionSource = "manual" | "workspace" | "case";

export interface Indicator {
  type: IndicatorType;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  confidence: number | null;
  tags: string[];
  source: string | null;
  notes: string | null;
}

export interface Collection {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
  source: CollectionSource;
  linked_case_ids: string[];
  linked_workspace_ids: string[];
  metadata: Record<string, unknown>;
  indicators: Indicator[];
}

/** One row of `listCollections`/`searchCollections` — metadata only, no
 *  `indicators` (a collection's indicator list can grow large; see
 *  `indicator_count`). The full list is available from `getCollection`. */
export interface CollectionListItem {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
  tags: string[];
  source: CollectionSource;
  created_at: string;
  updated_at: string;
  linked_case_ids: string[];
  linked_workspace_ids: string[];
  metadata: Record<string, unknown>;
  indicator_count: number;
}

export interface CreateCollectionRequest {
  name: string;
  description?: string | null;
  category?: string | null;
  tags?: string[];
  source?: CollectionSource;
  metadata?: Record<string, unknown>;
}

/** Every field is optional; an omitted field leaves the saved value unchanged. */
export interface UpdateCollectionRequest {
  name?: string;
  description?: string | null;
  category?: string | null;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface AddIndicatorRequest {
  type: IndicatorType;
  value: string;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number | null;
  tags?: string[];
  source?: string | null;
  notes?: string | null;
}

/** Identity used to match the indicator to remove: `(type, value)`,
 *  normalized server-side — not an exact string match. */
export interface RemoveIndicatorRequest {
  type: IndicatorType;
  value: string;
}

export interface CollectionListFilters {
  name?: string;
  category?: string;
  indicator_type?: IndicatorType;
  tag?: string;
  linked_case_id?: string;
  linked_workspace_id?: string;
}

export interface CollectionListResponse {
  collections: CollectionListItem[];
  total: number;
}

function buildQuery(filters: CollectionListFilters): string {
  const params = new URLSearchParams();
  if (filters.name) params.set("name", filters.name);
  if (filters.category) params.set("category", filters.category);
  if (filters.indicator_type) params.set("indicator_type", filters.indicator_type);
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.linked_case_id) params.set("linked_case_id", filters.linked_case_id);
  if (filters.linked_workspace_id) params.set("linked_workspace_id", filters.linked_workspace_id);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/** Create a new collection. */
export function createCollection(
  request: CreateCollectionRequest,
  signal?: AbortSignal,
): Promise<Collection> {
  return post<Collection>("/collections", request, signal);
}

/** Browse every collection (metadata only), most recently updated first.
 *  Unfiltered — see {@link searchCollections} for deterministic filtering. */
export function listCollections(signal?: AbortSignal): Promise<CollectionListResponse> {
  return get<CollectionListResponse>("/collections", signal);
}

/** Deterministically filter collections (metadata only). No fuzzy search, no AI. */
export function searchCollections(
  filters: CollectionListFilters = {},
  signal?: AbortSignal,
): Promise<CollectionListResponse> {
  return get<CollectionListResponse>(`/collections/search${buildQuery(filters)}`, signal);
}

/** Load one collection, including its full indicator list. */
export function getCollection(id: string, signal?: AbortSignal): Promise<Collection> {
  return get<Collection>(`/collections/${encodeURIComponent(id)}`, signal);
}

/** Partially update a collection's own metadata. */
export function updateCollection(
  id: string,
  request: UpdateCollectionRequest,
  signal?: AbortSignal,
): Promise<Collection> {
  return patch<Collection>(`/collections/${encodeURIComponent(id)}`, request, signal);
}

/** Delete a collection. Never touches any linked Workspace investigation or Case. */
export function deleteCollection(id: string, signal?: AbortSignal): Promise<void> {
  return del(`/collections/${encodeURIComponent(id)}`, signal);
}

/** Add one indicator to a collection. Deduplicated by `(type, normalized
 *  value)`; a matching existing indicator is merged rather than duplicated. */
export function addIndicator(
  id: string,
  request: AddIndicatorRequest,
  signal?: AbortSignal,
): Promise<Collection> {
  return post<Collection>(`/collections/${encodeURIComponent(id)}/indicator`, request, signal);
}

/** Remove one indicator from a collection, matched by `(type, normalized
 *  value)`. Idempotent — removing an identity that isn't present is a no-op. */
export function removeIndicator(
  id: string,
  request: RemoveIndicatorRequest,
  signal?: AbortSignal,
): Promise<Collection> {
  return delWithPayload<Collection>(
    `/collections/${encodeURIComponent(id)}/indicator`,
    request,
    signal,
  );
}

/** Link one Workspace investigation to a collection. Idempotent. */
export function linkWorkspaceToCollection(
  id: string,
  workspaceId: string,
  signal?: AbortSignal,
): Promise<Collection> {
  return post<Collection>(
    `/collections/${encodeURIComponent(id)}/workspace`,
    { workspace_id: workspaceId },
    signal,
  );
}

/** Link one Case to a collection. Idempotent. */
export function linkCaseToCollection(
  id: string,
  caseId: string,
  signal?: AbortSignal,
): Promise<Collection> {
  return post<Collection>(
    `/collections/${encodeURIComponent(id)}/case`,
    { case_id: caseId },
    signal,
  );
}
