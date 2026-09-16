import type { BatchPreviewResponse, InvestigationOptions } from "./api";
import type { BatchRow } from "@/hooks/useBatchInvestigation";

const DB_NAME = "threatlens-personal";
const STORE = "batch-sessions";
const KEY = "latest";
const MAX_AGE = 24 * 60 * 60 * 1000;

export interface StoredBatchSession {
  savedAt: number;
  preview: BatchPreviewResponse;
  rows: BatchRow[];
  options: InvestigationOptions;
}

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function saveBatchSession(session: StoredBatchSession): Promise<void> {
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE, "readwrite").objectStore(STORE).put(session, KEY);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}

export async function loadBatchSession(): Promise<StoredBatchSession | null> {
  const db = await database();
  const value = await new Promise<StoredBatchSession | undefined>((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(KEY);
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  db.close();
  if (!value || Date.now() - value.savedAt > MAX_AGE) { await clearBatchSession(); return null; }
  return { ...value, rows: value.rows.map((row) => row.state === "running" ? { ...row, state: "cancelled", error: "Interrupted by page reload.", errorCode: "interrupted", retryable: true } : row) };
}

export async function clearBatchSession(): Promise<void> {
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE, "readwrite").objectStore(STORE).delete(KEY);
    request.onsuccess = () => resolve(); request.onerror = () => reject(request.error);
  });
  db.close();
}
