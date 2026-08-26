"use client";

import { FormEvent, useState } from "react";
import { createClient } from "@/lib/supabase/browser";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    const { error } = await createClient().auth.signInWithPassword({ email, password });
    setBusy(false);
    if (error) { setMessage(error.message); return; }
    window.location.assign("/workspace");
  }

  return <main className="min-h-screen px-4 py-16"><div className="mx-auto max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
    <h1 className="text-xl font-semibold">Sign in to ThreatLens</h1>
    <p className="mt-1 text-sm text-zinc-500">Access saved investigations and detection review.</p>
    <form onSubmit={submit} className="mt-6 space-y-4">
      <label className="block text-sm text-zinc-300">Email<input required type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm" /></label>
      <label className="block text-sm text-zinc-300">Password<input required type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm" /></label>
      {message && <p role="alert" className="text-sm text-red-300">{message}</p>}
      <button disabled={busy} className="w-full rounded-lg bg-white px-3 py-2 text-sm font-medium text-zinc-900 disabled:opacity-50">{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  </div></main>;
}
