// Small, generic browser-side download helpers — no server involvement, no
// new dependency. Pure data in, DOM side effect out.

/** Strip everything but a safe, portable filename charset. */
export function sanitizeFilenameSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9-]/g, "");
}

/** Trigger a client-side download of `data` as a formatted JSON file. */
export function triggerJsonDownload(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
