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

/**
 * POST `body` to an API path and return the parsed JSON.
 *
 * Pass an {@link AbortSignal} to cancel an in-flight request; an abort
 * propagates as a `DOMException` named `AbortError` (re-thrown, not wrapped).
 */
export async function post<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the service.");
  }

  if (!res.ok) {
    let message = `Request failed (${res.status}).`;
    if (res.status === 422) message = "That request could not be processed.";
    throw new ApiError(message, res.status);
  }

  return (await res.json()) as T;
}

/** POST `{ query }` to an API path and return the parsed JSON. */
export function postQuery<T>(path: string, query: string, signal?: AbortSignal): Promise<T> {
  return post<T>(path, { query }, signal);
}

/** GET an API path and return the parsed JSON (used by read-only health checks). */
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { method: "GET", signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the service.");
  }
  if (!res.ok) throw new ApiError(`Request failed (${res.status}).`, res.status);
  return (await res.json()) as T;
}
