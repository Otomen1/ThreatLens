"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createClient } from "@/lib/supabase/browser";
import { isPrivateList, isRecoverableList, listRecovery, RECOVERY_STATE_KEY, type ListPosition } from "@/lib/listRecovery";
import { occupiedHeaderBottom } from "@/lib/uiLayout";

function internalUrl() { return `${window.location.pathname}${window.location.search}`; }
function pathOf(href: string) { return new URL(href, window.location.origin).pathname; }
function visible(element: HTMLElement) { return element.getClientRects().length > 0 && !element.closest("[hidden]"); }
function rowOf(anchor: HTMLAnchorElement): HTMLElement { return anchor.closest<HTMLElement>("[data-list-anchor], [data-ui-row], tr, [role=row]") ?? anchor; }

export function ListNavigationRecovery() {
  const pathname = usePathname();
  const params = useSearchParams();
  const url = `${pathname}${params.size ? `?${params}` : ""}`;
  const router = useRouter();
  const [navigationEvent, setNavigationEvent] = useState(0);
  const current = useRef<{ id: string; url: string } | null>(null);
  const pending = useRef<ListPosition | null>(null);
  const stopRestore = useRef<() => void>(() => {});
  const capture = useRef<(anchor?: HTMLAnchorElement, detail?: string) => void>(() => {});
  const account = useRef<string | null | undefined>(undefined);

  useEffect(() => {
    const incoming = window.history.state?.[RECOVERY_STATE_KEY];
    const returning = pending.current?.url === url ? pending.current : null;
    if (pending.current && !returning) pending.current = null;
    stopRestore.current();
    const id = returning?.id ?? (current.current?.url === url ? current.current.id : crypto.randomUUID());
    // Keep Next's own history fields; this opaque identifier contains no user data.
    if (incoming !== id) window.history.replaceState({ ...window.history.state, [RECOVERY_STATE_KEY]: id }, "");
    current.current = { id, url };
    if (!returning || !isRecoverableList(pathname)) return;

    let frame = 0;
    let restoring = false;
    let active = true;
    const finish = () => { if (!active) return; active = false; observer.disconnect(); cancelAnimationFrame(frame); clearTimeout(timer); if (pending.current === returning) pending.current = null; };
    const attempt = () => {
      if (restoring || internalUrl() !== url) return;
      const ready = [...document.querySelectorAll<HTMLElement>('[data-list-ready="true"]')].some(visible);
      if (!ready) return;
      restoring = true;
      // Let the selected rows, compact header and Next's own scroll handling settle.
      frame = requestAnimationFrame(() => { frame = requestAnimationFrame(() => {
        const link = returning.anchor ? [...document.querySelectorAll<HTMLAnchorElement>("main a[href]")].find((node) => visible(rowOf(node)) && `${node.pathname}${node.search}` === returning.anchor) : null;
        const anchor = returning.row ? document.querySelector<HTMLElement>(`[data-list-anchor="${CSS.escape(returning.row)}"]`) : link ? rowOf(link) : null;
        const y = anchor ? window.scrollY + anchor.getBoundingClientRect().top - returning.offset : returning.y;
        window.scrollTo({ top: Math.max(0, y), behavior: "instant" });
        finish();
      }); });
    };
    const observer = new MutationObserver(attempt);
    observer.observe(document.querySelector("[data-app-content]") ?? document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-list-ready", "hidden"] });
    const timer = setTimeout(finish, 8000);
    stopRestore.current = finish;
    attempt();
    return finish;
  }, [url, pathname, navigationEvent]);

  useEffect(() => {
    let frame = 0;
    capture.current = (anchor, detail) => {
      const entry = current.current;
      if (!entry || internalUrl() !== entry.url || pending.current || !isRecoverableList(pathOf(entry.url))) return;
      if (isPrivateList(pathOf(entry.url)) && !account.current) return;
      const candidates = [...document.querySelectorAll<HTMLAnchorElement>("main a[href]")].filter((node) => visible(node) && node.origin === window.location.origin && !isRecoverableList(node.pathname) && /\/(workspace|cases|threat-feed)\//.test(node.pathname));
      const chosen = anchor ?? candidates.find((node) => node.getBoundingClientRect().top >= occupiedHeaderBottom()) ?? null;
      const row = chosen ? rowOf(chosen) : null;
      listRecovery.save({ ...entry, y: window.scrollY, anchor: chosen ? `${chosen.pathname}${chosen.search}` : null, row: row?.dataset.listAnchor, offset: row?.getBoundingClientRect().top ?? 0, private: isPrivateList(pathOf(entry.url)), detail });
    };
    const onScroll = () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; capture.current(); }); };
    const cancel = () => { stopRestore.current(); };
    const onKey = (event: KeyboardEvent) => {
      if (["ArrowDown", "ArrowUp", "PageDown", "PageUp", "Home", "End", " "].includes(event.key) && !(event.target as Element)?.closest("input,textarea,select,[contenteditable]")) cancel();
    };
    const onClick = (event: MouseEvent) => {
      const anchor = (event.target as Element)?.closest<HTMLAnchorElement>("a[href]");
      if (!anchor || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.altKey || event.shiftKey || anchor.target || anchor.hasAttribute("download") || anchor.origin !== window.location.origin || anchor.hash) return;
      stopRestore.current();
      const destination = `${anchor.pathname}${anchor.search}`;
      const entry = current.current;
      if (entry && isRecoverableList(pathOf(entry.url)) && !isRecoverableList(anchor.pathname)) capture.current(anchor, anchor.pathname);
      if (isRecoverableList(anchor.pathname) && anchor.textContent?.trim().startsWith("←")) {
        const origin = listRecovery.origin(window.location.pathname, anchor.pathname);
        if (origin) { event.preventDefault(); pending.current = origin; router.push(origin.url, { scroll: false }); return; }
      }
      if (destination !== internalUrl()) pending.current = null;
    };
    const onPop = (event: PopStateEvent) => {
      capture.current();
      stopRestore.current();
      const record = listRecovery.get(event.state?.[RECOVERY_STATE_KEY]);
      pending.current = record?.url === internalUrl() ? record : null;
      // Next may commit its route effect before later popstate listeners run.
      setNavigationEvent((value) => value + 1);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("popstate", onPop);
    window.addEventListener("wheel", cancel, { passive: true });
    window.addEventListener("touchstart", cancel, { passive: true });
    document.addEventListener("keydown", onKey);
    document.addEventListener("click", onClick, true);
    return () => { cancelAnimationFrame(frame); stopRestore.current(); window.removeEventListener("scroll", onScroll); window.removeEventListener("popstate", onPop); window.removeEventListener("wheel", cancel); window.removeEventListener("touchstart", cancel); document.removeEventListener("keydown", onKey); document.removeEventListener("click", onClick, true); };
  }, [router]);

  useEffect(() => {
    let active = true;
    try {
      const client = createClient();
      const update = (id: string | null) => {
        if (!active) return;
        if (id === null || (account.current !== undefined && account.current !== id)) { listRecovery.clearPrivate(); if (pending.current?.private) stopRestore.current(); }
        account.current = id;
      };
      void client.auth.getSession().then(({ data }) => update(data.session?.user.id ?? null)).catch(() => update(null));
      const { data } = client.auth.onAuthStateChange((_event, session) => update(session?.user.id ?? null));
      return () => { active = false; data.subscription.unsubscribe(); };
    } catch { listRecovery.clearPrivate(); }
  }, []);
  return null;
}
