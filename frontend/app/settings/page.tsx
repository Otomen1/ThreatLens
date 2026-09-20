"use client";

import { useEffect, useState } from "react";
import { downloadBackup, getBackupHistory, restoreBackup, testBackup, validateBackup, type BackupHistoryEntry, type BackupPreview } from "@/lib/api";
import { getFeedSources, type FeedSource } from "@/lib/api/threatFeed";
import { useToast } from "@/components/ui/ToastProvider";

export default function SettingsPage() {
  const { notify } = useToast();
  const [bundle, setBundle] = useState<unknown>(null);
  const [preview, setPreview] = useState<BackupPreview | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<BackupHistoryEntry[]>([]);
  const [feedSources, setFeedSources] = useState<FeedSource[]>([]);
  const [confirmRestore, setConfirmRestore] = useState(false);

  useEffect(() => { void getBackupHistory().then((result) => setHistory(result.entries)).catch(() => undefined); }, []);
  useEffect(() => { void getFeedSources().then(setFeedSources).catch(() => undefined); }, []);

  async function verifyTestRestore() {
    if (!bundle || !preview?.valid) return;
    setBusy(true);
    try {
      const result = await testBackup(bundle);
      setMessage(result.valid ? "Test restore passed in isolated memory. Your live data was not changed." : result.errors.join(" "));
      setHistory((await getBackupHistory()).entries);
    } catch { setMessage("Test restore could not be completed."); }
    finally { setBusy(false); }
  }

  async function chooseFile(file: File | undefined) {
    setPreview(null);
    setMessage("");
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as unknown;
      setBundle(parsed);
      setBusy(true);
      setPreview(await validateBackup(parsed));
    } catch {
      setBundle(null);
      setMessage("This is not a valid ThreatLens backup file.");
    } finally {
      setBusy(false);
    }
  }

  async function restore() {
    if (!bundle || !preview?.valid) return;
    setConfirmRestore(false);
    try {
      setBusy(true);
      const result = await restoreBackup(bundle);
      setMessage(`Restore complete: ${result.investigations_added + result.cases_added} added, ${result.investigations_updated + result.cases_updated} updated, ${result.investigations_skipped + result.cases_skipped} kept.`);
      localStorage.removeItem("threatlens:navigation-summary:v1");
      window.dispatchEvent(new Event("threatlens:navigation-summary-invalidated"));
      notify("Backup restored with a safe merge.");
      setHistory((await getBackupHistory()).entries);
    } catch {
      setMessage("Restore failed. No records were intentionally deleted.");
      notify("Backup restore failed; no records were intentionally deleted.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function download() {
    setBusy(true);
    try {
      const blob = await downloadBackup();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "threatlens-backup.json";
      anchor.click();
      URL.revokeObjectURL(url);
      setMessage("Backup downloaded.");
      notify("Backup downloaded.");
    } catch {
      setMessage("Backup download failed.");
      notify("Backup download failed.", "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="mx-auto max-w-3xl space-y-6">
        <header><h1 className="text-2xl font-semibold">Settings</h1><p className="mt-1 text-sm text-zinc-500">Manage portable copies of your ThreatLens data.</p></header>
        <section data-focus="backup" tabIndex={-1} className="space-y-5 rounded-2xl border border-zinc-800 bg-zinc-900 p-5">
          <div><h2 className="font-medium text-white">Data Management</h2><p className="mt-1 text-sm text-zinc-500">Backups contain investigations, detection history, and cases. API keys and passwords are never included.</p></div>
          <button disabled={busy} type="button" onClick={() => void download()} className="inline-flex rounded-lg border border-sky-500/30 px-3 py-2 text-sm text-sky-300 hover:bg-sky-500/10 disabled:opacity-50">Download backup</button>
          <div className="border-t border-zinc-800 pt-5"><label className="block text-sm font-medium text-zinc-200" htmlFor="backup-file">Restore from backup</label><input id="backup-file" className="mt-3 block w-full rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-sm" type="file" accept="application/json,.json" onChange={(event) => void chooseFile(event.target.files?.[0])} /></div>
          {busy && <p className="text-sm text-zinc-400" role="status">Checking backup…</p>}
          {preview && <div className={`rounded-xl border p-4 text-sm ${preview.valid ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200" : "border-red-500/30 bg-red-500/10 text-red-200"}`}><p>{preview.valid ? "Backup is valid." : "Backup cannot be restored."}</p><p className="mt-1 text-xs opacity-80">{preview.investigations} investigations · {preview.cases} cases · {preview.conflicts} existing records</p>{preview.errors.map((error) => <p className="mt-1 text-xs" key={error}>{error}</p>)}</div>}
          {preview?.valid && <div className="space-y-3"><div className="flex flex-wrap gap-2"><button disabled={busy} type="button" onClick={() => void verifyTestRestore()} className="rounded-lg border border-sky-500/30 px-3 py-2 text-sm text-sky-300 hover:bg-sky-500/10 disabled:opacity-50">Test restore safely</button><button disabled={busy} type="button" onClick={() => setConfirmRestore(true)} className="rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50">Restore with safe merge</button></div>{confirmRestore && <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4" role="alertdialog" aria-labelledby="restore-confirmation-title"><p id="restore-confirmation-title" className="text-sm font-medium text-amber-100">Merge this backup into ThreatLens?</p><p className="mt-1 text-xs text-amber-200/70">Existing newer records will be kept. Nothing will be deleted.</p><div className="mt-3 flex gap-2"><button type="button" onClick={() => void restore()} className="rounded-lg bg-amber-500 px-3 py-2 text-sm font-medium text-black hover:bg-amber-400">Confirm restore</button><button type="button" onClick={() => setConfirmRestore(false)} className="rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800">Cancel</button></div></div>}</div>}
          {message && <p className="rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-sm text-zinc-300" role="status">{message}</p>}
          {history.length > 0 && <div className="border-t border-zinc-800 pt-5"><h3 className="text-sm font-medium text-zinc-200">Recent backup activity</h3><div className="mt-3 space-y-2">{history.slice(0, 6).map((entry) => <div key={`${entry.timestamp}-${entry.operation}`} className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs"><span className="capitalize text-zinc-300">{entry.operation} · {entry.status}</span><span className="text-zinc-500">{entry.investigations} investigations · {entry.cases} cases · {new Date(entry.timestamp).toLocaleString()}</span></div>)}</div><p className="mt-2 text-[11px] text-zinc-600">Activity history is process-local and resets when the server restarts.</p></div>}
        </section>
        <section className="space-y-4 rounded-2xl border border-zinc-800 bg-zinc-900 p-5"><div><h2 className="font-medium text-white">Threat Feed sources</h2><p className="mt-1 text-sm text-zinc-500">Passive source status. These checks never spend threat-intelligence quota.</p></div>{feedSources.map((source) => <div key={source.id} className="flex flex-col gap-2 rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-sm sm:flex-row sm:items-center sm:justify-between"><div><p className="text-zinc-200">{source.name}</p><p className="text-xs text-zinc-600">{source.kind} · {source.last_success_at ? `last success ${new Date(source.last_success_at).toLocaleString()}` : "not refreshed yet"}</p></div><span className={`text-xs ${source.last_error_code ? "text-amber-300" : "text-emerald-300"}`}>{source.last_error_code ? source.last_error ?? source.last_error_code : source.enabled ? "Ready" : "Disabled"}</span></div>)}</section>
      </div>
    </main>
  );
}
