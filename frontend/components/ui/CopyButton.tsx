"use client";

import { useState } from "react";

import { useToast } from "./ToastProvider";

export function CopyButton({ value, label = "Copy", className = "" }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const { notify } = useToast();
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      notify(`${label} copied.`);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      notify("Clipboard access is unavailable.", "error");
    }
  }
  return <button type="button" onClick={() => void copy()} className={className}>{copied ? "Copied ✓" : label}</button>;
}
