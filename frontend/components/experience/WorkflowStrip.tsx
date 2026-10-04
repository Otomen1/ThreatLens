"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { saveInvestigation, updateInvestigation, type InvestigationResponse, type DetectionPackage } from "@/lib/api";
import { useSessionIdentity } from "@/hooks/useSessionIdentity";
import { useToast } from "@/components/ui/ToastProvider";
import { DataLocation } from "@/components/ui/DataLocation";
import { readPreferences } from "@/lib/experiencePreferences";
export function WorkflowStrip({ data, pkg, generate, savedId, onSaved }: { data: InvestigationResponse; pkg: DetectionPackage | null; generate: () => void; savedId?: string | null; onSaved?: (id: string) => void }) {
  const owner = useSessionIdentity();
  const [saved, setSaved] = useState<{ id: string; owner: string } | null>(null);
  const [savedPackage, setSavedPackage] = useState<DetectionPackage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [ambiguous, setAmbiguous] = useState(false);
  const live = useRef(true); const currentOwner = useRef(owner); const currentInvestigation = useRef(data.investigation_id);
  const { notify } = useToast();
  useEffect(() => { currentOwner.current = owner; currentInvestigation.current = data.investigation_id; setSaved(null); setSavedPackage(null); setError(""); setAmbiguous(false); setBusy(false); }, [owner, data.investigation_id]);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  const record = saved?.owner === owner ? saved : owner && savedId ? { id: savedId, owner } : null;
  async function save() {
    if (!owner || busy) return;
    const requestOwner = owner; const requestInvestigation = data.investigation_id; setBusy(true); setError("");
    try {
      const result = record ? await updateInvestigation(record.id, { detection_package: pkg }) : await saveInvestigation({ title: `${data.entity.type}: ${data.entity.value}`, investigation_type: data.entity.type, investigation_summary: data.investigation_summary, investigation_snapshot: data, detection_package: pkg });
      if (!live.current || currentOwner.current !== requestOwner || currentInvestigation.current !== requestInvestigation) return;
      setSaved({ id: result.id, owner: requestOwner }); setSavedPackage(pkg);
      onSaved?.(result.id);
      window.dispatchEvent(new Event("threatlens:navigation-summary-invalidated"));
      notify(record ? "Rules saved to this investigation." : "Investigation saved to Workspace.");
    } catch {
      if (!live.current || currentOwner.current !== requestOwner || currentInvestigation.current !== requestInvestigation) return;
      if (!record) setAmbiguous(true);
      setError(record ? "Rules could not be saved. The generated package remains available; retry saving without regenerating." : "The save could not be confirmed. Check Workspace before creating another record."); notify("Save could not be confirmed.", "error");
    } finally { if (live.current && currentOwner.current === requestOwner && currentInvestigation.current === requestInvestigation) setBusy(false); }
  }
  function exportPackage() {
    if (!pkg) return;
    const formats = readPreferences().formats;
    const artifacts = pkg.artifacts.filter((a) => !formats.length || formats.includes(a.language));
    const exported = { ...pkg, artifacts, languages: [...new Set(artifacts.map((a) => a.language))] };
    const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = "threatlens-detection-package.json"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); notify("Detection package exported.");
  }
  const button = "rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-300 disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-sky-500";
  return <section aria-label="Investigation workflow" className="space-y-3 rounded-xl border border-zinc-800 p-4">
    <p className="text-xs text-zinc-400">Investigated → {record ? "Saved" : "Not saved"} → {pkg ? `${pkg.artifacts.length} generated · ${pkg.artifacts.filter((a) => a.validation.status === "valid").length} validated · ${pkg.artifacts.filter((a) => a.review_status === "reviewed").length} reviewed · ${pkg.artifacts.filter((a) => a.review_status === "approved").length} approved` : "Not generated"} → Review → Export</p>
    <DataLocation kind={record ? "Saved to database" : "Temporary"} detail={pkg && pkg !== savedPackage ? "Generated rules have unsaved changes." : undefined} />
    <div className="flex flex-wrap gap-2">{!owner ? <Link href="/login" className={button}>Sign in to save</Link> : !record ? <button disabled={busy || ambiguous || !data.investigation_summary} className={button} onClick={() => void save()}>{busy ? "Saving…" : "Save to Workspace"}</button> : <><Link href={`/workspace/${record.id}`} className={button}>Saved · View in Workspace</Link>{pkg && pkg !== savedPackage && <button disabled={busy} className={button} onClick={() => void save()}>{busy ? "Saving rules…" : "Save rules to this investigation"}</button>}</>}
    <button className={button} disabled={!data.investigation_summary || Boolean(pkg)} onClick={generate}>Generate detections</button>
    {record && pkg === savedPackage && pkg && <Link className={button} href={`/detections?investigation=${encodeURIComponent(record.id)}`}>Review rules</Link>}
    <button className={button} disabled={!pkg?.artifacts.length} onClick={exportPackage}>Export rules</button></div>
    {!pkg && <p className="text-xs text-zinc-500">Generation is optional and requires eligible findings. It does not deploy or approve rules.</p>}
    {error && <p role="alert" className="text-amber-300">{error} <Link href="/workspace" className="underline">Inspect Workspace</Link>{ambiguous && <button className="ml-2 underline" onClick={() => setAmbiguous(false)}>I checked; allow another save</button>}</p>}
  </section>;
}
