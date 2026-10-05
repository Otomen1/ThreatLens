"use client";

import { useLayoutEffect, useRef, useState, type RefObject } from "react";
import { FeedSearchBox } from "./FeedWorkflow";

export function FeedHeader({ headerRef }: { headerRef: RefObject<HTMLElement | null> }) {
  const [compact, setCompact] = useState(false);
  const slot = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    let frame = 0;
    let isCompact = false;
    const measure = () => {
      frame = 0;
      const next = isCompact ? scrollY >= 64 : scrollY > 96;
      isCompact = next; setCompact(next);
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(measure); };
    const observer = new ResizeObserver(() => {
      if (!isCompact && headerRef.current && slot.current) slot.current.style.height = `${headerRef.current.getBoundingClientRect().height}px`;
    });
    if (headerRef.current) observer.observe(headerRef.current);
    window.addEventListener("scroll", schedule, { passive: true });
    schedule();
    return () => { cancelAnimationFrame(frame); observer.disconnect(); window.removeEventListener("scroll", schedule); };
  }, [headerRef]);
  return <div ref={slot} className="feed-header-slot">
    <header ref={headerRef} data-pinned-header data-compact={compact} aria-label="Threat Feed search controls" className="fixed inset-x-0 top-14 z-30 border-b border-zinc-800 bg-zinc-950">
      <div className={`threat-feed-frame px-4 ${compact ? "py-3" : "py-4 sm:py-6"}`}>
        <h1 className={`${compact ? "text-lg" : "text-3xl"} font-semibold`}>Threat Feed</h1>
        <FeedSearchBox compact={compact} />
      </div>
    </header>
  </div>;
}
