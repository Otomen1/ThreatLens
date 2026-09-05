"use client";

import { useState } from "react";
import { restoreBackup, validateBackup, type BackupPreview } from "@/lib/api";

export default function SettingsPage() {
  const [bundle, setBundle] = useState<unknown>(null);
  const [preview, setPreview] = useState<BackupPreview | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

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
          {preview?.valid && <button disabled={busy} type="button" onClick={() => void restore()} className="rounded-lg bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50">Restore with safe merge</button>}
          {message && <p className="rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-sm text-zinc-300" role="status">{message}</p>}
        </section>
      </div>
    </main>
  );
}
