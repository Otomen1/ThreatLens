"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { occupiedHeaderBottom } from "@/lib/uiLayout";

/** A non-interactive visual copy leaves each original table's semantics intact. */
export function TableHeadings() {
  const pathname = usePathname();
  useEffect(() => {
    const root = document.querySelector<HTMLElement>("[data-app-content]");
    if (!root) return;
    const layer = document.createElement("div");
    layer.className = "floating-table-headings";
    layer.setAttribute("aria-hidden", "true");
    document.body.append(layer);
    let tables: HTMLElement[] = [];
    let frame = 0;
    let needsScan = true;
    const measure = () => {
      frame = 0;
      if (needsScan) {
        tables = Array.from(root.querySelectorAll<HTMLElement>('main table, main [role="table"]'));
        needsScan = false;
      }
      const top = occupiedHeaderBottom();
      document.documentElement.style.setProperty("--occupied-header-bottom", `${top}px`);
      const children: HTMLElement[] = [];
      for (const table of tables) {
        if (!table.isConnected) continue;
        const heading = table.querySelector<HTMLElement>('thead tr, [role="row"]:has([role="columnheader"])');
        if (!heading || heading.querySelector("button,input,select,a")) continue;
        const box = table.getBoundingClientRect();
        const head = heading.getBoundingClientRect();
        if (!head.height || head.top >= top || box.bottom <= top + head.height) continue;
        let left = Math.max(0, box.left), right = Math.min(innerWidth, box.right);
        for (let parent = table.parentElement; parent && parent !== root; parent = parent.parentElement) {
          if (/(auto|scroll|hidden|clip)/.test(getComputedStyle(parent).overflowX)) {
            const clip = parent.getBoundingClientRect();
            left = Math.max(left, clip.left); right = Math.min(right, clip.right);
          }
        }
        if (right <= left) continue;
        const copy = document.createElement("div");
        copy.className = "floating-table-heading";
        Object.assign(copy.style, { top: `${top}px`, left: `${left}px`, width: `${right - left}px`, height: `${head.height}px` });
        for (const cell of heading.children) {
          const bounds = cell.getBoundingClientRect();
          const style = getComputedStyle(cell);
          const label = document.createElement("span");
          label.textContent = cell.textContent;
          Object.assign(label.style, { position: "absolute", left: `${bounds.left - left}px`, width: `${bounds.width}px`, height: `${head.height}px`, padding: style.padding, fontSize: style.fontSize, fontWeight: style.fontWeight, textAlign: style.textAlign, display: "flex", alignItems: "center" });
          copy.append(label);
        }
        children.push(copy);
      }
      layer.replaceChildren(...children);
    };
    const schedule = () => { if (!frame) frame = requestAnimationFrame(measure); };
    const observer = new MutationObserver(() => { needsScan = true; schedule(); });
    observer.observe(root, { childList: true, subtree: true });
    const resize = new ResizeObserver(schedule);
    resize.observe(root);
    window.addEventListener("scroll", schedule, { capture: true, passive: true });
    window.addEventListener("resize", schedule);
    schedule();
    return () => {
      cancelAnimationFrame(frame); observer.disconnect(); resize.disconnect(); layer.remove();
      window.removeEventListener("scroll", schedule, true); window.removeEventListener("resize", schedule);
      document.documentElement.style.removeProperty("--occupied-header-bottom");
    };
  }, [pathname]);
  return null;
}
