"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  ["/", "Search"],
  ["/workspace", "Workspace"],
  ["/detections", "Detections"],
  ["/cases", "Cases"],
  ["/dashboard", "Dashboard"],
  ["/exposure", "Exposure"],
  ["/identity", "Identity"],
  ["/correlation", "Correlation"],
] as const;

export function AppNav() {
  const pathname = usePathname();
  return (
    <nav className="sticky top-0 z-40 border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur" aria-label="Primary navigation">
      <div className="max-w-6xl mx-auto px-4 h-14 flex items-center gap-5">
        <Link href="/" className="text-sm font-semibold tracking-tight text-white mr-2">ThreatLens</Link>
        <div className="flex items-center gap-1 overflow-x-auto">
          {links.map(([href, label]) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return <Link key={href} href={href} className={`shrink-0 rounded-lg px-3 py-1.5 text-xs transition-colors ${active ? "bg-zinc-800 text-white" : "text-zinc-500 hover:text-zinc-200 hover:bg-zinc-900"}`}>{label}</Link>;
          })}
        </div>
        <Link href="/login" className="ml-auto shrink-0 rounded-lg px-3 py-1.5 text-xs text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200">Sign in</Link>
      </div>
    </nav>
  );
}
