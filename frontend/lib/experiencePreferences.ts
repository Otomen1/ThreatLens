import { useEffect, useState } from "react";

export const FORMATS = ["sigma", "yara", "suricata", "snort", "splunk_spl", "sentinel_kql", "elastic_eql", "elastic_esql", "chronicle_yara_l", "qradar_aql", "crowdstrike", "trend_vision_one", "stellar_cyber", "generic"];
export type ExperiencePreferences = { scanMode: "fast" | "standard" | "full"; formats: string[]; view: "compact" | "card"; pageSize: number; collapsed: string[] };
export const DEFAULT_PREFERENCES: ExperiencePreferences = { scanMode: "standard", formats: [], view: "compact", pageSize: 20, collapsed: ["detections"] };
export const PREFERENCES_KEY = "threatlens.experience.v1";
function sanitize(p: Partial<ExperiencePreferences>): ExperiencePreferences {
  return { scanMode: ["fast", "standard", "full"].includes(p.scanMode ?? "") ? p.scanMode! : "standard",
    formats: Array.isArray(p.formats) ? [...new Set(p.formats.filter((v) => typeof v === "string" && FORMATS.includes(v)))] : [],
    view: p.view === "card" ? "card" : "compact", pageSize: [10, 20, 50].includes(p.pageSize ?? 0) ? p.pageSize! : 20,
    collapsed: Array.isArray(p.collapsed) ? [...new Set(p.collapsed.filter((v) => typeof v === "string" && ["assessment", "providers", "detections"].includes(v)))] : [...DEFAULT_PREFERENCES.collapsed] };
}
export function readPreferences(): ExperiencePreferences {
  try {
    const record = JSON.parse(localStorage.getItem(PREFERENCES_KEY) ?? "null");
    if (!record || record.version !== 1) return DEFAULT_PREFERENCES;
    return sanitize(record.value ?? {});
  } catch { return DEFAULT_PREFERENCES; }
}
export function writePreferences(change: Partial<ExperiencePreferences>) {
  try { localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ version: 1, value: sanitize({ ...readPreferences(), ...change }) })); } catch { /* Optional local preferences. */ }
  window.dispatchEvent(new Event("threatlens:preferences"));
}
export function resetPreferences() {
  try { localStorage.removeItem(PREFERENCES_KEY); } catch { /* Optional storage. */ }
  window.dispatchEvent(new Event("threatlens:preferences"));
}
export function useExperiencePreferences() {
  const [preferences, setPreferences] = useState(DEFAULT_PREFERENCES);
  useEffect(() => { const load = () => setPreferences(readPreferences()); load(); window.addEventListener("threatlens:preferences", load); window.addEventListener("storage", load); return () => { window.removeEventListener("threatlens:preferences", load); window.removeEventListener("storage", load); }; }, []);
  return preferences;
}
