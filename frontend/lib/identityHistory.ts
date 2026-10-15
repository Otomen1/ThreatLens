import type { IdentityEmailCheckResponse } from "./api";
import { assertPrivateOwner } from "./privateSession";

const DB_NAME = "threatlens-identity", STORE = "email-checks";
const RETENTION = 90 * 24 * 60 * 60 * 1000;
const MAX_PER_EMAIL = 20;
export interface IdentityHistoryRecord { id: string; ownerId?: string; email: string; checkedAt: string; response: IdentityEmailCheckResponse; }
export function validIdentityHistory(value: unknown): value is IdentityHistoryRecord {
  if (!value || typeof value !== "object") return false;
  const item = value as IdentityHistoryRecord;
  const stamp = Date.parse(item.checkedAt);
  return typeof item.id === "string" && typeof item.email === "string" && item.email.length <= 320
    && Number.isFinite(stamp) && stamp <= Date.now() + 60_000 && Date.now() - stamp <= RETENTION
    && !!item.response && Array.isArray(item.response.summary?.findings)
    && typeof item.response.summary.entity_value === "string"
    && !!item.response.summary.statistics && !!item.response.summary.metadata
    && item.response.summary.findings.every((finding) => !!finding
      && typeof finding.provider === "string" && typeof finding.status === "string"
      && typeof finding.summary === "string" && Array.isArray(finding.evidence)
      && finding.evidence.every((evidence) => !!evidence && typeof evidence.type === "string"
        && typeof evidence.summary === "string" && !!evidence.data && typeof evidence.data === "object"))
    && item.response.checked_at === item.checkedAt;
}
function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      const db = request.result;
      const store = db.objectStoreNames.contains(STORE) ? request.transaction!.objectStore(STORE) : db.createObjectStore(STORE, { keyPath: "id" });
      if (!store.indexNames.contains("owner")) store.createIndex("owner", "ownerId");
    };
    request.onsuccess = () => resolve(request.result);
  });
}
async function operate<T>(owner: string, mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
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
export async function identityHistory(owner: string, email?: string): Promise<IdentityHistoryRecord[]> {
  const raw = await operate<IdentityHistoryRecord[]>(owner, "readonly", (store) => store.index("owner").getAll(owner));
  const counts = new Map<string, number>();
  const valid = raw.filter(validIdentityHistory).toSorted((a, b) => Date.parse(b.checkedAt) - Date.parse(a.checkedAt)).filter((record) => {
    const count = (counts.get(record.email) ?? 0) + 1; counts.set(record.email, count); return count <= MAX_PER_EMAIL;
  });
  const keep = new Set(valid.map((record) => record.id));
  const removed = raw.filter((record) => !keep.has(record.id));
  if (removed.length) await operate(owner, "readwrite", (store) => {
    for (const record of removed) store.delete(record.id);
    return store.count();
  });
  return valid.filter((record) => !email || record.email === email.trim().toLowerCase());
}
export async function saveIdentityHistory(owner: string, email: string, response: IdentityEmailCheckResponse): Promise<void> {
  const normalized = email.trim().toLowerCase();
  const record: IdentityHistoryRecord = { id: `${owner}|${normalized}|${response.checked_at}`, ownerId: owner, email: normalized, checkedAt: response.checked_at, response };
  if (!validIdentityHistory(record)) throw new Error("Invalid identity result");
  await operate(owner, "readwrite", (store) => store.put(record));
  await identityHistory(owner);
}
export async function clearIdentityHistory(owner: string, email?: string): Promise<void> {
  const records = await operate<IdentityHistoryRecord[]>(owner, "readonly", (store) => store.index("owner").getAll(owner));
  await operate(owner, "readwrite", (store) => {
    for (const record of records) if (!email || record.email === email.trim().toLowerCase()) store.delete(record.id);
    return store.count();
  });
}
async function legacyRecords(owner: string) {
  const records = await operate<IdentityHistoryRecord[]>(owner, "readonly", (store) => store.getAll());
  return records.filter((record) => !record.ownerId);
}
export async function hasLegacyIdentityHistory(owner: string) { return (await legacyRecords(owner)).length > 0; }
export async function migrateLegacyIdentityHistory(owner: string) {
  const records = await legacyRecords(owner);
  await operate(owner, "readwrite", (store) => {
    for (const record of records) {
      if (validIdentityHistory(record)) store.put({ ...record, ownerId: owner, id: `${owner}|${record.email}|${record.checkedAt}` });
      store.delete(record.id);
    }
    return store.count();
  });
  await identityHistory(owner);
}
export async function deleteLegacyIdentityHistory(owner: string) {
  const records = await legacyRecords(owner);
  await operate(owner, "readwrite", (store) => { for (const record of records) store.delete(record.id); return store.count(); });
}
