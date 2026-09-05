import { post } from "./client";

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

export function validateBackup(bundle: unknown): Promise<BackupPreview> {
  return post<BackupPreview>("/backup/validate", bundle);
}

export function restoreBackup(bundle: unknown): Promise<RestoreResult> {
  return post<RestoreResult>("/backup/restore", bundle);
}
