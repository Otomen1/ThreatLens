// Browser-memory ownership only. Tokens and lookup data never enter this module.
let owner: string | null = null;
let generation = 0;
const pending = new Set<AbortController>();
export function privateOwner() { return owner; }
export function privateGeneration() { return generation; }
export function setPrivateOwner(next: string | null) {
  if (next === owner) return;
  owner = next; invalidatePrivateSession();
}
export function invalidatePrivateSession() {
  generation++;
  pending.forEach((controller) => controller.abort()); pending.clear();
  if (typeof window !== "undefined") window.dispatchEvent(new Event("threatlens:private-session"));
}
export function assertPrivateOwner(value: string) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value) || owner !== value) {
    throw new DOMException("Private session changed", "AbortError");
  }
}
export function trackPrivateRequest(controller: AbortController) {
  pending.add(controller);
  return () => pending.delete(controller);
}
