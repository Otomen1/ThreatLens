"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  checkIdentityEmail,
  identityFrameworkStatus,
  passwordHashRange,
  type IdentityEmailCheckResponse,
  type IdentityFrameworkStatus,
} from "@/lib/api";
import {
  clearIdentityHistory,
  identityHistory,
  saveIdentityHistory,
  type IdentityHistoryRecord,
} from "@/lib/identityHistory";
import { checkPasswordExposure } from "@/lib/passwordExposure";

type Tab = "email" | "password";
type Notice = { tone: "error" | "success" | "info"; message: string } | null;

function breachCount(result: IdentityEmailCheckResponse | null): number {
  if (!result) return 0;
  return result.summary.findings.reduce((total, finding) => total + finding.evidence.length, 0);
}

function exposedClasses(result: IdentityEmailCheckResponse): string[] {
  const values = new Set<string>();
  for (const finding of result.summary.findings) {
    for (const evidence of finding.evidence) {
      const classes = evidence.data.data_classes;
      if (Array.isArray(classes)) {
        for (const value of classes) if (typeof value === "string") values.add(value);
      }
    }
  }
  return [...values].toSorted();
}

function ProviderDiagnostics({ status }: { status: IdentityFrameworkStatus | null }) {
  if (!status) return null;
  return (
    <section className="rounded-2xl border border-zinc-800 bg-zinc-900 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Provider diagnostics</h2>
          <p className="mt-1 text-xs text-zinc-500">No active probe or additional quota is used.</p>
        </div>
        <span className={`rounded-full border px-2.5 py-1 text-xs ${status.enabled ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-zinc-700 text-zinc-400"}`}>
          {status.enabled ? "Enabled" : "Disabled"}
        </span>
      </div>
      <div className="mt-4 space-y-2">
        {status.providers.map((provider) => (
          <div key={provider.name} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-zinc-800 bg-zinc-950/50 px-4 py-3 text-sm">
            <span className="text-zinc-200">{provider.display_name}</span>
            <span className={provider.status === "operational" ? "text-emerald-300" : "text-amber-300"}>
              {!provider.enabled ? "Disabled" : !provider.configured ? "API key not configured" : provider.status}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function IdentityPage() {
  const [tab, setTab] = useState<Tab>("email");
  const [status, setStatus] = useState<IdentityFrameworkStatus | null>(null);
  const [email, setEmail] = useState("");
  const [emailResult, setEmailResult] = useState<IdentityEmailCheckResponse | null>(null);
  const [previous, setPrevious] = useState<IdentityHistoryRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [passwordCount, setPasswordCount] = useState<number | null>(null);
  const [confirmClear, setConfirmClear] = useState<"email" | "all" | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    identityFrameworkStatus(controller.signal)
      .then(setStatus)
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setNotice({ tone: "error", message: error instanceof Error ? error.message : "Could not load identity status." });
        }
      });
    return () => controller.abort();
  }, []);

  async function runEmailCheck(refresh: boolean) {
    const normalized = email.trim().toLowerCase();
    if (!normalized) return;
    setBusy(true);
    setNotice(null);
    try {
      const history = await identityHistory(normalized);
      const result = await checkIdentityEmail(normalized, refresh);
      setPrevious(history[0] ?? null);
      setEmailResult(result);
      await saveIdentityHistory(normalized, result);
      setNotice({ tone: "success", message: result.cache_status === "hit" ? "Cached identity result loaded." : "Identity check completed." });
    } catch (error) {
      setNotice({ tone: "error", message: error instanceof Error ? error.message : "Identity check failed." });
    } finally {
      setBusy(false);
    }
  }

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = passwordRef.current;
    const password = input?.value ?? "";
    if (!password) return;
    if (input) input.value = "";
    setBusy(true);
    setNotice({ tone: "info", message: "Hashing locally and checking the exposure dataset…" });
    try {
      setPasswordCount(await checkPasswordExposure(password, passwordHashRange));
      setNotice({ tone: "success", message: "Password exposure check completed. The password was not transmitted or stored." });
    } catch (error) {
      setPasswordCount(null);
      setNotice({ tone: "error", message: error instanceof Error ? error.message : "Password dataset is unavailable." });
    } finally {
      setBusy(false);
    }
  }

  async function clearHistory(scope: "email" | "all") {
    await clearIdentityHistory(scope === "email" ? email.trim().toLowerCase() : undefined);
    setPrevious(null);
    if (scope === "email") setEmailResult(null);
    setConfirmClear(null);
    setNotice({ tone: "success", message: scope === "email" ? "History for this email was cleared." : "All browser-local identity history was cleared." });
  }

  const currentCount = breachCount(emailResult);
  const previousCount = previous ? breachCount(previous.response) : null;
  const failedFinding = emailResult?.summary.findings.find((finding) =>
    ["error", "timeout", "rate_limited", "unauthorized"].includes(finding.status),
  );
  const lookupCompleted = emailResult?.summary.findings.some((finding) =>
    ["ok", "not_found"].includes(finding.status),
  ) ?? false;
  const dataClasses = useMemo(
    () => (emailResult ? exposedClasses(emailResult) : []),
    [emailResult],
  );

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="mx-auto w-full max-w-5xl space-y-6">
        <header>
          <Link href="/" className="text-xs text-zinc-500 transition-colors hover:text-zinc-300">← Back to Search</Link>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">Identity Intelligence</h1>
          <p className="mt-1 max-w-3xl text-sm text-zinc-500">Check source-reported email and password exposure. Results are descriptive and never a “safe” or “compromised” verdict.</p>
        </header>

        <div className="flex gap-1 rounded-xl border border-zinc-800 bg-zinc-900 p-1" role="tablist" aria-label="Identity checks">
          {(["email", "password"] as const).map((value) => (
            <button key={value} role="tab" aria-selected={tab === value} onClick={() => { setTab(value); setNotice(null); }} className={`flex-1 rounded-lg px-4 py-2 text-sm font-medium transition ${tab === value ? "bg-zinc-700 text-white" : "text-zinc-500 hover:text-zinc-200"}`}>
              {value === "email" ? "Email Exposure" : "Password Exposure"}
            </button>
          ))}
        </div>

        {notice && <div role="status" className={`rounded-xl border px-4 py-3 text-sm ${notice.tone === "error" ? "border-red-500/30 bg-red-500/10 text-red-300" : notice.tone === "success" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-sky-500/30 bg-sky-500/10 text-sky-300"}`}>{notice.message}</div>}

        {tab === "email" ? (
          <section className="space-y-5 rounded-2xl border border-zinc-800 bg-zinc-900 p-5 sm:p-6">
            <form onSubmit={(event) => { event.preventDefault(); void runEmailCheck(false); }} className="flex flex-col gap-3 sm:flex-row">
              <label className="sr-only" htmlFor="identity-email">Email address</label>
              <input id="identity-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" className="min-w-0 flex-1 rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-3 text-sm text-white outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20" />
              <button disabled={busy} className="rounded-xl bg-white px-5 py-3 text-sm font-semibold text-black disabled:opacity-50">{busy ? "Checking…" : "Check email"}</button>
              {emailResult && <button type="button" disabled={busy} onClick={() => void runEmailCheck(true)} className="rounded-xl border border-zinc-700 px-4 py-3 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-50">Refresh now</button>}
            </form>

            {!status?.enabled && <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">Email checks are disabled. Set IDENTITY_ENABLED=true and configure HIBP_API_KEY to enable them.</p>}

            {emailResult && (
              <div className="space-y-5">
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-4"><p className="text-xs uppercase tracking-wide text-zinc-500">Reported breaches</p><p className="mt-2 text-2xl font-semibold text-white">{currentCount}</p></div>
                  <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-4"><p className="text-xs uppercase tracking-wide text-zinc-500">Cache</p><p className="mt-2 text-sm font-medium capitalize text-zinc-200">{emailResult.cache_status}</p></div>
                  <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-4"><p className="text-xs uppercase tracking-wide text-zinc-500">Change</p><p className="mt-2 text-sm font-medium text-zinc-200">{previousCount === null ? "No earlier check" : `${currentCount - previousCount >= 0 ? "+" : ""}${currentCount - previousCount} since last check`}</p></div>
                </div>

                {failedFinding && <div role="alert" className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">{failedFinding.error?.message ?? "The identity provider could not complete this lookup."}{failedFinding.error?.retryable ? " You can try Refresh now." : ""}</div>}

                {dataClasses.length > 0 && <div><h2 className="text-sm font-semibold text-white">Exposed data categories</h2><div className="mt-2 flex flex-wrap gap-2">{dataClasses.map((value) => <span key={value} className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-300">{value}</span>)}</div></div>}

                <div className="space-y-3">
                  <h2 className="text-sm font-semibold text-white">Breach history</h2>
                  {lookupCompleted && currentCount === 0 ? <p className="rounded-xl border border-zinc-800 p-4 text-sm text-zinc-400">This email was not found in the configured exposure dataset. This is not a guarantee of safety.</p> : !lookupCompleted ? <p className="rounded-xl border border-zinc-800 p-4 text-sm text-zinc-400">No completed provider result is available.</p> : emailResult.summary.findings.flatMap((finding) => finding.evidence).map((evidence, index) => (
                    <article key={`${evidence.summary}-${index}`} className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-2"><h3 className="font-medium text-white">{evidence.value || evidence.summary}</h3><span className="text-xs text-zinc-500">{String(evidence.data.breach_date || "Date not reported")}</span></div>
                      <p className="mt-2 text-xs text-zinc-500">Source-reported by Have I Been Pwned</p>
                    </article>
                  ))}
                </div>

                <div className="flex flex-wrap gap-2 border-t border-zinc-800 pt-4">
                  {confirmClear === "email" ? <><button onClick={() => void clearHistory("email")} className="rounded-lg border border-red-500/40 px-3 py-2 text-xs text-red-300">Confirm clear this email</button><button onClick={() => setConfirmClear(null)} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300">Cancel</button></> : <button onClick={() => setConfirmClear("email")} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-400">Clear this email history</button>}
                  {confirmClear === "all" ? <><button onClick={() => void clearHistory("all")} className="rounded-lg border border-red-500/40 px-3 py-2 text-xs text-red-300">Confirm clear all history</button><button onClick={() => setConfirmClear(null)} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300">Cancel</button></> : <button onClick={() => setConfirmClear("all")} className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-400">Clear all identity history</button>}
                </div>
              </div>
            )}
          </section>
        ) : (
          <section className="space-y-5 rounded-2xl border border-zinc-800 bg-zinc-900 p-5 sm:p-6">
            <div><h2 className="text-base font-semibold text-white">Check a password privately</h2><p className="mt-1 text-sm text-zinc-500">Your browser hashes the password first. Only the first five hash characters are sent, and neither the password nor its full hash is stored.</p></div>
            <form onSubmit={(event) => void submitPassword(event)} className="flex flex-col gap-3 sm:flex-row">
              <label className="sr-only" htmlFor="identity-password">Password to check</label>
              <input ref={passwordRef} id="identity-password" type="password" autoComplete="off" required placeholder="Enter a password to check" className="min-w-0 flex-1 rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-3 text-sm text-white outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20" />
              <button disabled={busy} className="rounded-xl bg-white px-5 py-3 text-sm font-semibold text-black disabled:opacity-50">{busy ? "Checking…" : "Check password"}</button>
            </form>
            {passwordCount !== null && <div className={`rounded-xl border p-5 ${passwordCount > 0 ? "border-amber-500/30 bg-amber-500/10" : "border-emerald-500/30 bg-emerald-500/10"}`}><p className={`text-lg font-semibold ${passwordCount > 0 ? "text-amber-200" : "text-emerald-200"}`}>{passwordCount > 0 ? `Found ${passwordCount.toLocaleString()} time${passwordCount === 1 ? "" : "s"} in the exposure dataset` : "Not found in this exposure dataset"}</p><p className="mt-2 text-sm text-zinc-400">{passwordCount > 0 ? "Stop using this password and replace it anywhere it is reused." : "This result is not a guarantee that the password is safe. Use a unique password and a password manager."}</p></div>}
          </section>
        )}

        <ProviderDiagnostics status={status} />
        <p className="text-xs leading-relaxed text-zinc-600">Email history stays in this browser for up to 90 days and is not included in ThreatLens backups. Password checks are never added to history.</p>
      </div>
    </main>
  );
}
