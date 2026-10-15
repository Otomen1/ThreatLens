"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { createClient } from "@/lib/supabase/browser";
import { invalidatePrivateSession, setPrivateOwner } from "@/lib/privateSession";

type OwnerSession = { userId: string | null; status: "checking" | "signed_out" | "owner" | "blocked" | "unavailable" };
const initial: OwnerSession = { userId: null, status: "checking" };
const Context = createContext<OwnerSession>(initial);
export const useOwnerSession = () => useContext(Context);

export function OwnerSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<OwnerSession>(initial);
  const known = useRef<string | null>(null);
  useEffect(() => {
    let active = true, revision = 0, observed = false;
    let request: AbortController | null = null;
    const clear = (status: OwnerSession["status"]) => {
      known.current = null; setPrivateOwner(null); invalidatePrivateSession();
      if (active) setSession({ userId: null, status });
    };
    if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY) {
      clear("unavailable"); return;
    }
    const client = createClient();
    const verify = async (subject: string | null, token?: string) => {
      const current = ++revision;
      request?.abort(); request = new AbortController();
      if (!subject || !token) { clear("signed_out"); return; }
      if (known.current !== subject) clear("checking");
      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL ?? "/api/v1"}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }, cache: "no-store", signal: request.signal,
        });
        if (!active || current !== revision) return;
        if (!response.ok) { clear(response.status === 403 ? "blocked" : response.status === 401 ? "signed_out" : "unavailable"); return; }
        const body = await response.json();
        if (!active || current !== revision) return;
        if (body.owner !== true || body.user_id !== subject) { clear("blocked"); return; }
        known.current = subject; setPrivateOwner(subject); setSession({ userId: subject, status: "owner" });
      } catch { if (active && current === revision) clear("unavailable"); }
    };
    void client.auth.getSession().then(({ data }) => {
      if (active && !observed) void verify(data.session?.user.id ?? null, data.session?.access_token);
    }).catch(() => { if (active && !observed) clear("unavailable"); });
    const { data } = client.auth.onAuthStateChange((_event, value) => {
      observed = true;
      // No awaited Supabase calls inside its auth callback (avoids its auth lock).
      void verify(value?.user.id ?? null, value?.access_token);
    });
    return () => { active = false; revision++; request?.abort(); data.subscription.unsubscribe(); setPrivateOwner(null); };
  }, []);
  return <Context.Provider value={session}>{children}</Context.Provider>;
}

const PRIVATE = ["/workspace", "/detections", "/cases", "/settings", "/identity", "/dashboard", "/exposure", "/correlation"];
export function PrivateSessionBoundary({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const session = useOwnerSession();
  if (!PRIVATE.some((path) => pathname === path || pathname.startsWith(`${path}/`))) return children;
  if (session.status !== "owner") return <main className="mx-auto max-w-3xl px-4 py-12" role="status">
    <h1 className="text-xl">Personal workspace</h1>
    <p className="mt-3 text-zinc-400">{session.status === "checking" ? "Checking owner access…" : session.status === "blocked" ? "This workspace is restricted to its owner." : session.status === "unavailable" ? "Owner access could not be verified. Private data is not loaded." : "Sign in to access your private workspace."}</p>
    <Link className="mt-4 inline-block text-sky-300 underline" href="/login">Sign in</Link>
  </main>;
  return <div key={session.userId}>{children}</div>;
}
