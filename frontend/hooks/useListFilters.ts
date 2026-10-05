"use client";
import { useCallback, useEffect, useState } from "react";

export type FilterDefinition = Record<string, readonly string[]>;
export function parseListFilters(params: URLSearchParams, definition: FilterDefinition): Record<string, string> {
  return Object.fromEntries(Object.entries(definition).map(([key, allowed]) => {
    const value = params.get(key) ?? "";
    return [key, value.length <= 512 && (!allowed.length || allowed.includes(value)) ? value : ""];
  }));
}

export function useListFilters(definition: FilterDefinition) {
  const [filters, setFilters] = useState<Record<string, string>>(() => parseListFilters(new URLSearchParams(), definition));
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    const load = () => { setFilters(parseListFilters(new URLSearchParams(window.location.search), definition)); setHydrated(true); };
    load(); window.addEventListener("popstate", load);
    return () => window.removeEventListener("popstate", load);
  }, [definition]);
  const update = useCallback((key: string, value: string) => {
    if (!(key in definition)) return;
    const params = new URLSearchParams(window.location.search);
    value ? params.set(key, value) : params.delete(key);
    const next = parseListFilters(params, definition);
    next[key] ? params.set(key, next[key]) : params.delete(key);
    if (key !== "page") params.delete("page");
    setFilters(next);
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${params.size ? `?${params}` : ""}`);
  }, [definition]);
  return { filters, update, hydrated };
}
