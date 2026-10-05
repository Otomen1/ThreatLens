"use client";

import { useEffect, useRef, useState, type RefObject } from "react";
import Link from "next/link";

/** Keep one set of links so docking preserves keyboard focus and semantics. */
export function FeedViewNavigation({ selected, headerRef, onDockChange }: {
  selected: string | null;
  headerRef: RefObject<HTMLElement | null>;
  onDockChange: (docked: boolean) => void;
}) {
  const slotRef = useRef<HTMLDivElement>(null);
  const [placement, setPlacement] = useState({ docked: false, top: 200 });

  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 1024px)");
    let frame = 0;
    let docked = false;
    const measure = () => {
      frame = 0;
      const slot = slotRef.current;
      const header = headerRef.current;
      if (!slot || !header) return;
      const bottom = header.getBoundingClientRect().bottom;
      // The slot stays in flow; hysteresis avoids flicker near the boundary.
      const distance = slot.getBoundingClientRect().bottom - bottom;
      const next = desktop.matches && (docked ? distance < 8 : distance < -8);
      docked = next;
      setPlacement((previous) => previous.docked === next && previous.top === bottom + 16
        ? previous : { docked: next, top: bottom + 16 });
      onDockChange(next);
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(measure); };
    const observer = new ResizeObserver(schedule);
    if (headerRef.current) observer.observe(headerRef.current);
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    desktop.addEventListener("change", schedule);
    schedule();
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      desktop.removeEventListener("change", schedule);
    };
  }, [headerRef, onDockChange]);

  return <div ref={slotRef} className="mt-6 lg:h-[53px]">
    <nav aria-label="Threat Feed views" data-docked={placement.docked}
      style={placement.docked ? { top: placement.top, maxHeight: `calc(100dvh - ${placement.top + 16}px)` } : undefined}
      className={placement.docked
        ? "feed-side-navigation fixed left-4 z-20 flex w-36 flex-col gap-1 overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-950 p-2 shadow-lg"
        : "flex flex-wrap gap-2 border-b border-zinc-800 pb-3"}>
      {(["news", "vulnerabilities", "poc", "iocs"] as const).map((tab) => <Link key={tab}
        aria-current={selected === tab ? "page" : undefined}
        className={`rounded-lg px-3 py-2 text-sm capitalize focus-visible:outline focus-visible:outline-sky-400 ${selected === tab ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-900"}`}
        href={`/threat-feed?tab=${tab}`}>{tab === "poc" ? "PoC & Tools" : tab === "iocs" ? "IOC Reports" : tab === "news" ? "News" : "Vulnerabilities"}</Link>)}
    </nav>
  </div>;
}
