import type { IdentityEmailCheckResponse } from "./api";

const DB_NAME = "threatlens-identity";
const STORE_NAME = "email-checks";
const DB_VERSION = 1;
const MAX_PER_EMAIL = 20;
const RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

export interface IdentityHistoryRecord {
  id: string;
  email: string;
  checkedAt: string;
  response: IdentityEmailCheckResponse;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        const store = database.createObjectStore(STORE_NAME, { keyPath: "id" });
        store.createIndex("email", "email");
        store.createIndex("checkedAt", "checkedAt");
      }
    };
    request.onsuccess = () => resolve(request.result);
  });
}

function complete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

export async function identityHistory(email?: string): Promise<IdentityHistoryRecord[]> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const source = email
      ? transaction.objectStore(STORE_NAME).index("email")
      : transaction.objectStore(STORE_NAME);
    const request = email ? source.getAll(email.toLowerCase()) : source.getAll();
    const records = await new Promise<IdentityHistoryRecord[]>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result as IdentityHistoryRecord[]);
      request.onerror = () => reject(request.error);
    });
    return records.toSorted((left, right) => right.checkedAt.localeCompare(left.checkedAt));
  } finally {
    database.close();
  }
}

export async function saveIdentityHistory(
  email: string,
  response: IdentityEmailCheckResponse,
): Promise<void> {
  const normalized = email.trim().toLowerCase();
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put({
      id: `${normalized}|${response.checked_at}`,
      email: normalized,
      checkedAt: response.checked_at,
      response,
    } satisfies IdentityHistoryRecord);
    await complete(transaction);
  } finally {
    database.close();
  }
  await pruneIdentityHistory(normalized);
}

async function pruneIdentityHistory(email: string): Promise<void> {
  const records = await identityHistory();
  const cutoff = Date.now() - RETENTION_MS;
  const forEmail = records.filter((record) => record.email === email);
  const remove = new Set([
    ...records.filter((record) => Date.parse(record.checkedAt) < cutoff).map((record) => record.id),
    ...forEmail.slice(MAX_PER_EMAIL).map((record) => record.id),
  ]);
  if (remove.size === 0) return;
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    for (const id of remove) transaction.objectStore(STORE_NAME).delete(id);
    await complete(transaction);
  } finally {
    database.close();
  }
}

export async function clearIdentityHistory(email?: string): Promise<void> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(STORE_NAME, "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    if (!email) {
      store.clear();
    } else {
      const request = store.index("email").openKeyCursor(IDBKeyRange.only(email.toLowerCase()));
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;
        store.delete(cursor.primaryKey);
        cursor.continue();
      };
    }
    await complete(transaction);
  } finally {
    database.close();
  }
}
