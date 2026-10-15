import type { BatchPreviewResponse, InvestigationOptions } from "./api";
import type { BatchRow } from "@/hooks/useBatchInvestigation";
import { assertPrivateOwner } from "./privateSession";

const DB_NAME = "threatlens-personal";
const STORE = "batch-sessions";
const MAX_AGE = 24 * 60 * 60 * 1000;
export interface StoredBatchSession {
  savedAt: number; preview: BatchPreviewResponse; rows: BatchRow[]; options: InvestigationOptions;
}
export function validBatchSession(value: unknown): value is StoredBatchSession {
  if (!value || typeof value !== "object") return false;
  const item = value as StoredBatchSession;
  return Number.isFinite(item.savedAt) && item.savedAt <= Date.now() + 60_000 && Date.now() - item.savedAt <= MAX_AGE
    && !!item.preview && Array.isArray(item.preview.entities) && item.preview.entities.length <= 20
    && !!item.options && ["fast", "standard", "full"].includes(item.options.scanMode ?? "standard")
    && Array.isArray(item.rows) && item.rows.length <= 20 && item.rows.every((row) => row
      && row.entity && typeof row.entity.normalized_value === "string"
      && ["queued", "running", "completed", "failed", "cancelled"].includes(row.state)
      && (row.investigation === null || typeof row.investigation === "object"));
}
function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE); };
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
}
async function transaction<T>(owner: string, mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  assertPrivateOwner(owner);
  const db = await database();
  try {
    assertPrivateOwner(owner);
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = action(tx.objectStore(STORE));
      const changed = () => { try { assertPrivateOwner(owner); } catch { try { tx.abort(); } catch { /* Transaction already completed. */ } } };
      window.addEventListener("threatlens:private-session", changed);
      tx.oncomplete = () => { window.removeEventListener("threatlens:private-session", changed); resolve(request.result); };
      const failed = () => { window.removeEventListener("threatlens:private-session", changed); reject(tx.error ?? new DOMException("Session changed", "AbortError")); };
      tx.onerror = failed; tx.onabort = failed;
    });
  } finally { db.close(); }
}
export async function saveBatchSession(owner: string, session: StoredBatchSession): Promise<void> {
  if (!validBatchSession(session)) throw new Error("Invalid or expired batch session");
  await transaction(owner, "readwrite", (store) => store.put(session, `owner:${owner}`));
}
export async function loadBatchSession(owner: string): Promise<StoredBatchSession | null> {
  const value = await transaction<unknown>(owner, "readonly", (store) => store.get(`owner:${owner}`));
  if (!validBatchSession(value)) { await clearBatchSession(owner); return null; }
  return { ...value, rows: value.rows.map((row) => row.state === "running" || row.state === "queued" ? { ...row, state: "cancelled", error: "Interrupted by page reload.", errorCode: "interrupted", retryable: true } : row) };
}
export async function clearBatchSession(owner: string): Promise<void> {
  await transaction(owner, "readwrite", (store) => store.delete(`owner:${owner}`));
}
export async function hasLegacyBatch(owner: string): Promise<boolean> {
  return (await transaction<unknown>(owner, "readonly", (store) => store.get("latest"))) !== undefined;
}
export async function migrateLegacyBatch(owner: string): Promise<void> {
  const value = await transaction<unknown>(owner, "readonly", (store) => store.get("latest"));
  if (validBatchSession(value)) {
    const existing = await loadBatchSession(owner);
    if (!existing) await saveBatchSession(owner, value);
  }
  await deleteLegacyBatch(owner);
}
export async function deleteLegacyBatch(owner: string): Promise<void> {
  await transaction(owner, "readwrite", (store) => store.delete("latest"));
}
