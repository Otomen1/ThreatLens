export const RECOVERY_TTL = 30 * 60_000;
export const RECOVERY_LIMIT = 50;
export const RECOVERY_STATE_KEY = "threatlensListEntry";
const lists = new Set(["/threat-feed", "/workspace", "/cases", "/detections"]);

export function isRecoverableList(pathname: string): boolean { return lists.has(pathname); }
export function isPrivateList(pathname: string): boolean { return pathname !== "/threat-feed"; }

export type ListPosition = {
  id: string; url: string; y: number; anchor: string | null; offset: number;
  private: boolean; savedAt: number; detail?: string; row?: string;
};

// Positions and original URLs live only in this tab's memory, never browser storage.
export class ListRecoveryStore {
  private entries = new Map<string, ListPosition>();
  constructor(private now: () => number = Date.now) {}
  private prune() {
    for (const [id, item] of this.entries) if (this.now() - item.savedAt >= RECOVERY_TTL) this.entries.delete(id);
    while (this.entries.size > RECOVERY_LIMIT) this.entries.delete(this.entries.keys().next().value!);
  }
  save(position: Omit<ListPosition, "savedAt">) {
    const previous = this.entries.get(position.id);
    this.entries.delete(position.id);
    this.entries.set(position.id, { ...position, detail: position.detail ?? previous?.detail, savedAt: this.now() });
    this.prune();
  }
  get(id: string): ListPosition | undefined { this.prune(); return this.entries.get(id); }
  origin(detail: string, listPath: string): ListPosition | undefined {
    this.prune();
    return [...this.entries.values()].reverse().find((item) => item.detail === detail && item.url.split("?")[0] === listPath);
  }
  clearPrivate() { for (const [id, item] of this.entries) if (item.private) this.entries.delete(id); }
  get size() { this.prune(); return this.entries.size; }
}
export const listRecovery = new ListRecoveryStore();
