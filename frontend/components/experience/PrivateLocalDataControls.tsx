"use client";
import { useEffect, useState } from "react";
import { useSessionIdentity } from "@/hooks/useSessionIdentity";
import { clearBatchSession, deleteLegacyBatch, hasLegacyBatch, migrateLegacyBatch } from "@/lib/batchSession";
import { clearIdentityHistory, deleteLegacyIdentityHistory, hasLegacyIdentityHistory, migrateLegacyIdentityHistory } from "@/lib/identityHistory";

type Action = "batch" | "identity" | "import" | "legacy";
export function PrivateLocalDataControls() {
  const owner = useSessionIdentity();
  const [legacy, setLegacy] = useState(false);
  const [confirm, setConfirm] = useState<Action | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!owner) return;
    let active = true;
    void Promise.all([hasLegacyBatch(owner), hasLegacyIdentityHistory(owner)]).then((values) => { if (active) setLegacy(values.some(Boolean)); }).catch(() => { if (active) setMessage("Browser-local data could not be inspected."); });
    return () => { active = false; };
  }, [owner]);
  async function apply() {
    if (!owner || !confirm) return;
    setBusy(true); setMessage("");
    try {
      if (confirm === "batch") await clearBatchSession(owner);
      if (confirm === "identity") await clearIdentityHistory(owner);
      if (confirm === "import") { await migrateLegacyBatch(owner); await migrateLegacyIdentityHistory(owner); setLegacy(false); }
      if (confirm === "legacy") { await deleteLegacyBatch(owner); await deleteLegacyIdentityHistory(owner); setLegacy(false); }
      setMessage(confirm === "import" ? "Valid legacy records imported into your account partition." : "Selected local records deleted. Other data is unchanged."); setConfirm(null);
    } catch { setMessage("The local operation could not finish. Your database records are unchanged; you may retry."); }
    finally { setBusy(false); }
  }
  const button = "rounded-lg border border-zinc-700 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-50";
  return <section className="space-y-3 rounded-2xl border border-zinc-800 bg-zinc-900 p-5" aria-label="Private browser data">
    <h2 className="font-medium">Private browser data</h2>
    <p className="text-xs text-zinc-400">Batch recovery (24 hours) and email history (90 days, latest 20 per email) belong to your verified account. They remain after sign-out but private views are cleared. They are not in server backups.</p>
    <p className="text-xs text-zinc-500">Anyone inspecting this browser profile directly may still access local storage. Use your own browser profile on shared computers.</p>
    <div className="flex flex-wrap gap-2"><button className={button} disabled={busy} onClick={() => setConfirm("batch")}>Delete local batch recovery</button><button className={button} disabled={busy} onClick={() => setConfirm("identity")}>Delete local identity history</button></div>
    {legacy && <div className="space-y-2 rounded-lg border border-amber-800 p-3"><p className="text-sm text-amber-200">Older unscoped browser records exist. They are hidden until you explicitly import them. Import only if they belong to you.</p><button className={button} disabled={busy} onClick={() => setConfirm("import")}>Import my legacy history</button><button className={`${button} ml-2`} disabled={busy} onClick={() => setConfirm("legacy")}>Delete legacy history</button></div>}
    {confirm && <div role="alert" className="space-y-3"><p>{confirm === "import" ? "Confirm these legacy records belong to you and import them?" : "Delete the selected browser-local records? Investigations, bookmarks and preferences will not change."}</p><button className={button} disabled={busy} onClick={() => void apply()}>{confirm === "import" ? "Confirm legacy import" : "Confirm local deletion"}</button><button className={`${button} ml-2`} disabled={busy} onClick={() => setConfirm(null)}>Cancel</button></div>}
    {message && <p role="status" className="text-sm text-zinc-300">{message}</p>}
  </section>;
}
