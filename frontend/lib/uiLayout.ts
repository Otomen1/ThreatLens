/** Read the actual occupied viewport edge, not a guessed header height. */
export function occupiedHeaderBottom(): number {
  let bottom = 0;
  for (const node of document.querySelectorAll<HTMLElement>('nav[aria-label="Primary navigation"], [data-pinned-header]')) {
    const box = node.getBoundingClientRect();
    if (box.top <= bottom + 16 && box.bottom > 0) bottom = Math.max(bottom, box.bottom);
  }
  return bottom;
}
