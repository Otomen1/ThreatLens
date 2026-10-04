"use client";
import { useEffect, useState } from "react";
import { createClient } from "@/lib/supabase/browser";
export function useSessionIdentity() {
  const [id, setId] = useState<string | null>(null);
  useEffect(() => {
    if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY) return;
    let live = true; let changed = false;
    const client = createClient();
    void client.auth.getUser().then(({ data }) => { if (live && !changed) setId(data.user?.id ?? null); }).catch(() => undefined);
    const { data } = client.auth.onAuthStateChange((_event, session) => { changed = true; if (live) setId(session?.user.id ?? null); });
    return () => { live = false; data.subscription.unsubscribe(); };
  }, []);
  return id;
}
