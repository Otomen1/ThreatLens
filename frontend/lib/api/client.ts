// Shared transport primitives for the ThreatLens API client. Every subsystem
// module in lib/api/ builds on these; nothing here is subsystem-specific.

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api/v1";

/** Error raised for any non-success API response or unreachable backend. */
export class ApiError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function accessToken(): Promise<string | undefined> {
  if (
    typeof window === "undefined"
    || !process.env.NEXT_PUBLIC_SUPABASE_URL
    || !process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  ) return undefined;
  const { createClient } = await import("@/lib/supabase/browser");
  const { data } = await createClient().auth.getSession();
  return data.session?.access_token;
}

function errorMessage(status: number): string {
  if (status === 401) return "Please sign in again.";
  if (status === 404) return "Not found.";
  if (status === 409) return "That change is not allowed from the current state.";
  if (status === 413) return "That file is too large.";
  if (status === 422) return "That request could not be processed.";
  return `Request failed (${status}).`;
}

/** Fetch an API path with the signed-in user's Supabase access token. */
export async function authorizedFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = await accessToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  try {
    return await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError("Could not reach the service.");
  }
}

async function request<T>(
  path: string,
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  body?: unknown,
  signal?: AbortSignal,
  cache?: RequestCache,
): Promise<T> {
  const headers = body === undefined ? undefined : { "Content-Type": "application/json" };
  const response = await authorizedFetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
    cache,
  });
  if (!response.ok) throw new ApiError(errorMessage(response.status), response.status);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function post<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(path, "POST", body, signal);
}

export function postQuery<T>(path: string, query: string, signal?: AbortSignal): Promise<T> {
  return post<T>(path, { query }, signal);
}

export function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, "GET", undefined, signal);
}

export function getUncached<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, "GET", undefined, signal, "no-store");
}

export function put<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(path, "PUT", body, signal);
}

export function patch<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(path, "PATCH", body, signal);
}

export function del(path: string, signal?: AbortSignal): Promise<void> {
  return request<void>(path, "DELETE", undefined, signal);
}

export function delWithBody<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>(path, "DELETE", undefined, signal);
}
