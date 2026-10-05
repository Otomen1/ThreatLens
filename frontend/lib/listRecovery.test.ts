import { describe, expect, it } from "vitest";
import { ListRecoveryStore, RECOVERY_TTL, isRecoverableList } from "./listRecovery";
import { parseListFilters } from "@/hooks/useListFilters";

const position = (id: string, privateEntry = false) => ({ id, url: privateEntry ? "/workspace?status=open" : "/threat-feed?tab=iocs", y: 750, anchor: "/threat-feed/ioc-reports/one", offset: 210, private: privateEntry });
describe("transient list recovery", () => {
  it("keeps at most 50 recent entries and expires after 30 minutes", () => {
    let now = 0; const store = new ListRecoveryStore(() => now);
    for (let i = 0; i < 51; i++) store.save(position(String(i)));
    expect(store.size).toBe(50); expect(store.get("0")).toBeUndefined();
    now = RECOVERY_TTL; expect(store.size).toBe(0);
  });
  it("retains source identity through scroll captures, without mixing identical URLs", () => {
    const store = new ListRecoveryStore(); store.save({ ...position("a"), detail: "/threat-feed/ioc-reports/one" });
    store.save({ ...position("a"), y: 900 }); store.save(position("b"));
    expect(store.origin("/threat-feed/ioc-reports/one", "/threat-feed")?.id).toBe("a");
    expect(store.get("a")?.y).toBe(900); expect(store.get("b")?.y).toBe(750);
    expect(store.origin("/unrelated", "/threat-feed")).toBeUndefined();
  });
  it("clears private entries without discarding public feed positions", () => {
    const store = new ListRecoveryStore(); store.save(position("public")); store.save(position("private", true));
    store.clearPrivate(); expect(store.size).toBe(1); expect(store.get("private")).toBeUndefined();
  });
  it("limits recovery to intended list routes", () => { expect(isRecoverableList("/workspace")).toBe(true); expect(isRecoverableList("/identity")).toBe(false); expect(isRecoverableList("/workspace/one")).toBe(false); });
  it("validates URL filters without returning unknown or oversized fields", () => {
    expect(parseListFilters(new URLSearchParams({ q: "hello", status: "wrong", token: "secret", owner: "a".repeat(513) }), { q: [], status: ["", "open"], owner: [] })).toEqual({ q: "hello", status: "", owner: "" });
  });
});
