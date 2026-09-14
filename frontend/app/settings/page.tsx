"use client";

import { useEffect, useState } from "react";
import { getBackupHistory, restoreBackup, testBackup, validateBackup, type BackupHistoryEntry, type BackupPreview } from "@/lib/api";

export default function SettingsPage() {
  const [bundle, setBundle] = useState<unknown>(null);
  const [preview, setPreview] = useState<BackupPreview | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<BackupHistoryEntry[]>([]);

  useEffect(() => { void getBackupHistory().then((result) => setHistory(result.entries)).catch(() => undefined); }, []);

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
    if (!window.confirm("Merge this backup into ThreatLens? Existing newer records will be kept.")) return;
    try {
      setBusy(true);
      const result = await restoreBackup(bundle);
      setMessage(`Restore complete: ${result.investigations_added + result.cases_added} added, ${result.investigations_updated + result.cases_updated} updated, ${result.investigations_skipped + result.cases_skipped} kept.`);
      setHistory((await getBackupHistory()).entries);
    } catch {
      setMessage("Restore failed. No records were intentionally deleted.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="mx-auto max-w-3xl space-y-6">
        <header><h1 className="text-2xl font-semibold">Settings</h1><p className="mt-1 text-sm text-zinc-500">Manage portable copies of your ThreatLens data.</p></header>
        <section className="space-y-5 rounded-2xl border border-zinc-800 bg-zinc-900 p-5">
          <div><h2 className="font-medium text-white">Data Management</h2><p className="mt-1 text-sm text-zinc-500">Backups contain investigations, detection history, and cases. API keys and passwords are never included.</p></div>
          <a href="/api/v1/backup" download className="inline-flex rounded-lg border border-sky-500/30 px-3 py-2 text-sm text-sky-300 hover:bg-sky-500/10">Download backup</a>
          <div className="border-t border-zinc-800 pt-5"><label className="block text-sm font-medium text-zinc-200" htmlFor="backup-file">Restore from backup</label><input id="backup-file" className="mt-3 block w-full rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-sm" type="file" accept="application/json,.json" onChange={(event) => void chooseFile(event.target.files?.[0])} /></div>
          {busy && <p className="text-sm text-zinc-400" role="status">Checking backup…</p>}
          {preview && <div className={`rounded-xl border p-4 text-sm ${preview.valid ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200" : "border-red-500/30 bg-red-500/10 text-red-200"}`}><p>{preview.valid ? "Backup is valid." : "Backup cannot be restored."}</p><p className="mt-1 text-xs opacity-80">{preview.investigations} investigations · {preview.cases} cases · {preview.conflicts} existing records</p>{preview.errors.map((error) => <p className="mt-1 text-xs" key={error}>{error}</p>)}</div>}
          {preview?.valid && <div className="flex flex-wrap gap-2"><button disabled={busy} type="button" onClick={() => void verifyTestRestore()} className="rounded-lg border border-sky-500/30 px-3 py-2 text-sm text-sky-300 hover:bg-sky-500/10 disabled:opacity-50">Test restore safely</button><button disabled={busy} type="button" onClick={() => void restore()} className="rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50">Restore with safe merge</button></div>}
          {message && <p className="rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-sm text-zinc-300" role="status">{message}</p>}
          {history.length > 0 && <div className="border-t border-zinc-800 pt-5"><h3 className="text-sm font-medium text-zinc-200">Recent backup activity</h3><div className="mt-3 space-y-2">{history.slice(0, 6).map((entry) => <div key={`${entry.timestamp}-${entry.operation}`} className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs"><span className="capitalize text-zinc-300">{entry.operation} · {entry.status}</span><span className="text-zinc-500">{entry.investigations} investigations · {entry.cases} cases · {new Date(entry.timestamp).toLocaleString()}</span></div>)}</div><p className="mt-2 text-[11px] text-zinc-600">Activity history is process-local and resets when the server restarts.</p></div>}
        </section>
      </div>
    </main>
  );
}
