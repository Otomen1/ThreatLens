"use client";

import { useState } from "react";

export type FeedSelection = {
  selected: Set<string>;
  toggle: (id: string) => void;
  toggleAll: () => void;
  clear: () => void;
};

export function useFeedSelection(scope: string, items: { id: string }[]): FeedSelection {
  const [state, setState] = useState<{ scope: string; ids: string[] }>({ scope, ids: [] });
  // Forget the previous page, including when Back later returns to its filters.
  if (state.scope !== scope) setState({ scope, ids: [] });
  const visible = new Set(items.map((item) => item.id));
  const selected = new Set(state.scope === scope ? state.ids.filter((id) => visible.has(id)) : []);
  return {
    selected,
    toggle: (id) => setState((current) => {
      const ids = new Set(current.scope === scope ? current.ids.filter((value) => visible.has(value)) : []);
      if (visible.has(id)) { if (ids.has(id)) ids.delete(id); else ids.add(id); }
      return { scope, ids: [...ids] };
    }),
    toggleAll: () => setState({ scope, ids: selected.size === visible.size ? [] : [...visible] }),
    clear: () => setState({ scope, ids: [] }),
  };
}
