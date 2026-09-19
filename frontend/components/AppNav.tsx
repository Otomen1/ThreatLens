"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { createClient } from "@/lib/supabase/browser";

type NavItem = { href: string; label: string };
type MenuName = "workspace" | "intelligence";

const PUBLIC_LINKS: NavItem[] = [
  { href: "/", label: "Search" },
  { href: "/threat-feed", label: "Threat Feed" },
];
const WORKSPACE_LINKS: NavItem[] = [
  { href: "/workspace", label: "Investigations" },
  { href: "/detections", label: "Detections" },
  { href: "/cases", label: "Cases" },
];
const INTELLIGENCE_LINKS: NavItem[] = [
  { href: "/exposure", label: "Exposure" },
  { href: "/identity", label: "Identity" },
  { href: "/correlation", label: "Correlation" },
];

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

function NavLink({ item, pathname, onNavigate }: { item: NavItem; pathname: string; onNavigate?: () => void }) {
  const active = isActive(pathname, item.href);
  return (
    <Link href={item.href} onClick={onNavigate} aria-current={active ? "page" : undefined} className={`rounded-lg px-3 py-1.5 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${active ? "bg-zinc-800 text-white" : "text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200"}`}>
      {item.label}
    </Link>
  );
}

function NavMenu({ name, label, href, items, pathname, openMenu, setOpenMenu }: { name: MenuName; label: string; href: string; items: NavItem[]; pathname: string; openMenu: MenuName | null; setOpenMenu: (menu: MenuName | null) => void }) {
  const open = openMenu === name;
  const active = items.some((item) => isActive(pathname, item.href));
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
  }, []);

  function openOnHover() {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    closeTimer.current = null;
    setOpenMenu(name);
  }

  function closeAfterPointerLeaves() {
    closeTimer.current = setTimeout(() => setOpenMenu(null), 180);
  }

  return (
    <div
      className="relative flex shrink-0 items-center"
      onMouseEnter={openOnHover}
      onMouseLeave={closeAfterPointerLeaves}
    >
      <Link href={href} aria-current={isActive(pathname, href) ? "page" : undefined} className={`rounded-l-lg py-1.5 pl-3 pr-1 text-xs transition-colors focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${active ? "bg-zinc-800 text-white" : "text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200"}`}>{label}</Link>
      <button type="button" aria-label={`Open ${label} menu`} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpenMenu(open ? null : name)} className={`rounded-r-lg py-1.5 pl-1 pr-2 text-xs transition-colors focus-visible:z-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${active ? "bg-zinc-800 text-zinc-300" : "text-zinc-600 hover:bg-zinc-900 hover:text-zinc-200"}`}>
        <span aria-hidden="true" className={`inline-block transition-transform ${open ? "rotate-180" : ""}`}>⌄</span>
      </button>
      {open && (
        <div role="menu" aria-label={label} className="absolute left-0 top-full mt-2 min-w-44 rounded-xl border border-zinc-800 bg-zinc-950 p-1.5 shadow-2xl shadow-black/40">
          {items.map((item) => <Link role="menuitem" key={item.href} href={item.href} onClick={() => setOpenMenu(null)} aria-current={isActive(pathname, item.href) ? "page" : undefined} className={`block rounded-lg px-3 py-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${isActive(pathname, item.href) ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-900 hover:text-white"}`}>{item.label}</Link>)}
        </div>
      )}
    </div>
  );
}

export function AppNav() {
  const pathname = usePathname();
  const router = useRouter();
  const navRef = useRef<HTMLElement>(null);
  const [signedIn, setSignedIn] = useState(false);
  const [openMenu, setOpenMenu] = useState<MenuName | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const client = createClient();
    client.auth.getUser().then(({ data }) => setSignedIn(Boolean(data.user)));
    const { data: subscription } = client.auth.onAuthStateChange((_event, session) => setSignedIn(Boolean(session?.user)));
    return () => subscription.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    setOpenMenu(null);
    setMobileOpen(false);
  }, [pathname]);

  useEffect(() => {
    function closeMenus(event: MouseEvent) {
      if (!navRef.current?.contains(event.target as Node)) setOpenMenu(null);
    }
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpenMenu(null);
        setMobileOpen(false);
      }
    }
    document.addEventListener("mousedown", closeMenus);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", closeMenus);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  async function signOut() {
    await createClient().auth.signOut();
    router.push("/");
    router.refresh();
  }

  const closeMobile = () => setMobileOpen(false);
  return (
    <nav ref={navRef} className="sticky top-0 z-40 border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur" aria-label="Primary navigation">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4">
        <Link href="/" className="mr-2 text-sm font-semibold tracking-tight text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500">ThreatLens</Link>
        <div className="hidden items-center gap-1 md:flex">
          {PUBLIC_LINKS.map((item) => <NavLink key={item.href} item={item} pathname={pathname} />)}
          {signedIn && <NavMenu name="workspace" label="Workspace" href="/workspace" items={WORKSPACE_LINKS} pathname={pathname} openMenu={openMenu} setOpenMenu={setOpenMenu} />}
          <NavMenu name="intelligence" label="Intelligence" href="/exposure" items={INTELLIGENCE_LINKS} pathname={pathname} openMenu={openMenu} setOpenMenu={setOpenMenu} />
          <NavLink item={{ href: "/dashboard", label: "Dashboard" }} pathname={pathname} />
          {signedIn && <NavLink item={{ href: "/settings", label: "Settings" }} pathname={pathname} />}
        </div>
        <div className="ml-auto hidden md:block">
          {signedIn ? <button type="button" onClick={signOut} className="rounded-lg px-3 py-1.5 text-xs text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500">Sign out</button> : <Link href="/login" className="rounded-lg px-3 py-1.5 text-xs text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500">Sign in</Link>}
        </div>
        <button type="button" aria-label="Toggle navigation menu" aria-expanded={mobileOpen} onClick={() => setMobileOpen((value) => !value)} className="ml-auto rounded-lg border border-zinc-800 px-3 py-1.5 text-xs text-zinc-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 md:hidden">{mobileOpen ? "Close" : "Menu"}</button>
      </div>
      {mobileOpen && (
        <div className="border-t border-zinc-800 bg-zinc-950 px-4 py-4 md:hidden">
          <div className="mx-auto grid max-w-6xl gap-4">
            <div className="grid grid-cols-2 gap-1">
              {PUBLIC_LINKS.map((item) => <NavLink key={item.href} item={item} pathname={pathname} onNavigate={closeMobile} />)}
              <NavLink item={{ href: "/dashboard", label: "Dashboard" }} pathname={pathname} onNavigate={closeMobile} />
              {signedIn && <NavLink item={{ href: "/settings", label: "Settings" }} pathname={pathname} onNavigate={closeMobile} />}
            </div>
            {signedIn && <MobileGroup label="Workspace" items={WORKSPACE_LINKS} pathname={pathname} onNavigate={closeMobile} />}
            <MobileGroup label="Intelligence" items={INTELLIGENCE_LINKS} pathname={pathname} onNavigate={closeMobile} />
            <div className="border-t border-zinc-800 pt-3">
              {signedIn ? <button type="button" onClick={signOut} className="w-full rounded-lg px-3 py-2 text-left text-xs text-zinc-400 hover:bg-zinc-900">Sign out</button> : <NavLink item={{ href: "/login", label: "Sign in" }} pathname={pathname} onNavigate={closeMobile} />}
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}

function MobileGroup({ label, items, pathname, onNavigate }: { label: string; items: NavItem[]; pathname: string; onNavigate: () => void }) {
  return (
    <section aria-label={label}>
      <p className="mb-1 px-3 text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-600">{label}</p>
      <div className="grid grid-cols-2 gap-1">{items.map((item) => <NavLink key={item.href} item={item} pathname={pathname} onNavigate={onNavigate} />)}</div>
    </section>
  );
}
