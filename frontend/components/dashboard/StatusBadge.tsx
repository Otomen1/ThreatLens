import type { ServiceState } from "@/lib/api";
import { statusBadgeClasses, statusDotClass, statusLabel } from "@/lib/dashboard";

export function StatusBadge({ status }: { status: ServiceState }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold uppercase tracking-wide ${statusBadgeClasses(status)}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${statusDotClass(status)}`} aria-hidden />
      {statusLabel(status)}
    </span>
  );
}
