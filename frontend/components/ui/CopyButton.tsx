"use client";

import { useEffect, useRef, useState } from "react";

import { useToast } from "./ToastProvider";

export function CopyButton({ value, label = "Copy", className = "", feedback = true }: { value: string; label?: string; className?: string; feedback?: boolean }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; if (timer.current) clearTimeout(timer.current); }; }, []);
  const { notify } = useToast();
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      if (!mounted.current) return;
      setCopied(true);
      notify(`${label} copied.`);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
    } catch {
      if (!mounted.current) return;
      if (timer.current) clearTimeout(timer.current);
      setCopied(false);
      notify("Clipboard access is unavailable.", "error");
    }
  }
  if (!feedback) return <button type="button" onClick={() => void copy()} className={className}>{copied ? "Copied ✓" : label}</button>;
  return <button type="button" aria-label={label} data-copied={copied} onClick={() => void copy()} className={`inline-flex items-center justify-center gap-2 ${className}`}><span aria-hidden="true" className="inline-flex h-4 w-4 shrink-0 items-center justify-center">{copied ? <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="m3 8 3 3 7-7" /></svg> : <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3"><rect x="5" y="5" width="8" height="8" rx="1.5" /><path d="M10 5V3a1 1 0 0 0-1-1H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2" /></svg>}</span><span>{label}</span><span role="status" className="sr-only">{copied ? `${label} copied.` : ""}</span></button>;
}
