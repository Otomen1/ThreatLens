"use client";

import { createContext, useCallback, useContext, useMemo, useState } from "react";

type ToastTone = "success" | "warning" | "error";
type Toast = { id: number; message: string; tone: ToastTone };
type ToastApi = { notify: (message: string, tone?: ToastTone) => void };

const ToastContext = createContext<ToastApi | null>(null);
let nextToastId = 1;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => setToasts((items) => items.filter((item) => item.id !== id)), []);
  const notify = useCallback((message: string, tone: ToastTone = "success") => {
    const id = nextToastId++;
    setToasts((items) => [...items.slice(-2), { id, message, tone }]);
    window.setTimeout(() => dismiss(id), tone === "error" ? 6000 : 3000);
  }, [dismiss]);
  const value = useMemo(() => ({ notify }), [notify]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-5 right-5 z-[70] flex w-[min(22rem,calc(100vw-2rem))] flex-col gap-2" aria-live="polite" aria-label="Notifications">
        {toasts.map((toast) => <div key={toast.id} role={toast.tone === "error" ? "alert" : "status"} className={`animate-ui-enter flex items-start gap-3 rounded-xl border px-4 py-3 text-sm shadow-2xl ${toast.tone === "success" ? "border-emerald-500/30 bg-emerald-950 text-emerald-200" : toast.tone === "warning" ? "border-amber-500/30 bg-amber-950 text-amber-200" : "border-red-500/30 bg-red-950 text-red-200"}`}>
          <span className="min-w-0 flex-1">{toast.message}</span>
          <button type="button" onClick={() => dismiss(toast.id)} aria-label="Dismiss notification" className="text-current opacity-60 hover:opacity-100">×</button>
        </div>)}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
