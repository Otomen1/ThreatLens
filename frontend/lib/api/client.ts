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
    if (res.status === 404) message = "Not found.";
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

/** PUT `body` to an API path and return the parsed JSON (used by the Workspace's update). */
export async function put<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "PUT",
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
    if (res.status === 404) message = "Not found.";
    if (res.status === 422) message = "That request could not be processed.";
    throw new ApiError(message, res.status);
  }

  return (await res.json()) as T;
}

/** PATCH `body` to an API path and return the parsed JSON (used by Case Management's partial update). */
export async function patch<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "PATCH",
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
    if (res.status === 404) message = "Not found.";
    if (res.status === 409) message = "That change is not allowed from the current state.";
    if (res.status === 422) message = "That request could not be processed.";
    throw new ApiError(message, res.status);
  }

  return (await res.json()) as T;
}

/** DELETE an API path. Resolves with no value on success (the API returns 204). */
export async function del(path: string, signal?: AbortSignal): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { method: "DELETE", signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the service.");
  }
  if (!res.ok) {
    const message = res.status === 404 ? "Not found." : `Request failed (${res.status}).`;
    throw new ApiError(message, res.status);
  }
}

/**
 * DELETE an API path and return the parsed JSON response body — for
 * endpoints that return the updated resource (e.g. unlinking a Workspace
 * investigation from a case) rather than a bare `204`. Prefer {@link del}
 * for the more common "204, no body" case.
 */
export async function delWithBody<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { method: "DELETE", signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("Could not reach the service.");
  }
  if (!res.ok) {
    const message = res.status === 404 ? "Not found." : `Request failed (${res.status}).`;
    throw new ApiError(message, res.status);
  }
  return (await res.json()) as T;
}

/**
 * DELETE an API path with a JSON request body, returning the parsed JSON
 * response body — for endpoints that identify what to delete via the body
 * rather than the path (e.g. removing an indicator from a collection, which
 * has no synthetic id of its own to put in the URL — identity is
 * `(type, value)`, given in the request body) and that return the updated
 * resource rather than a bare `204`.
 */
export async function delWithPayload<T>(
  path: string,
  body: unknown,
  signal?: AbortSignal,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "DELETE",
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
    if (res.status === 404) message = "Not found.";
    if (res.status === 422) message = "That request could not be processed.";
    throw new ApiError(message, res.status);
  }

  return (await res.json()) as T;
}
