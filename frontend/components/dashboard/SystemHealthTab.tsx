import type { SystemHealthResponse } from "@/lib/api";
import { formatTimestamp } from "@/lib/dashboard";

import { StatusBadge } from "./StatusBadge";

interface Props {
  data: SystemHealthResponse;
}

export function SystemHealthTab({ data }: Props) {
  return (
    <div className="space-y-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-white">Overall Status</h2>
          <p className="text-xs text-zinc-500 mt-1">
            Last checked {formatTimestamp(data.timestamp)}
          </p>
        </div>
        <StatusBadge status={data.status} />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {data.services.map((service) => (
          <div
            key={service.name}
            className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl p-4 space-y-2"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium text-zinc-200">{service.display_name}</span>
              <StatusBadge status={service.status} />
            </div>
            <p className="text-xs text-zinc-500 leading-relaxed">{service.detail}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
