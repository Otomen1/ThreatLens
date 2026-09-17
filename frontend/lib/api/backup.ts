import { ApiError, authorizedFetch, get, post } from "./client";

export interface BackupPreview {
  valid: boolean;
  investigations: number;
  cases: number;
  conflicts: number;
  errors: string[];
}

export interface RestoreResult {
  investigations_added: number;
  investigations_updated: number;
  investigations_skipped: number;
  cases_added: number;
  cases_updated: number;
  cases_skipped: number;
}

export interface BackupTestResult {
  valid: boolean; digest_verified: boolean; round_trip_verified: boolean;
  investigations: number; cases: number; errors: string[];
}

export interface BackupHistoryEntry {
  operation: string; status: string; timestamp: string; investigations: number; cases: number;
}

export function validateBackup(bundle: unknown): Promise<BackupPreview> {
  return post<BackupPreview>("/backup/validate", bundle);
}

export function restoreBackup(bundle: unknown): Promise<RestoreResult> {
  return post<RestoreResult>("/backup/restore", bundle);
}

export function testBackup(bundle: unknown): Promise<BackupTestResult> {
  return post<BackupTestResult>("/backup/test", bundle);
}

export function getBackupHistory(): Promise<{ entries: BackupHistoryEntry[] }> {
  return get<{ entries: BackupHistoryEntry[] }>("/backup/history");
}

export async function downloadBackup(): Promise<Blob> {
  const response = await authorizedFetch("/backup", { method: "GET" });
  if (!response.ok) throw new ApiError(`Request failed (${response.status}).`, response.status);
  return response.blob();
}
