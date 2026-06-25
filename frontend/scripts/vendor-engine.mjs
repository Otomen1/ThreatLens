// Build-time step for the Vercel deployment.
//
// The detection engine lives in ../backend, which is OUTSIDE the Vercel root
// directory (frontend/). Vercel's Python builder cannot reach above the root,
// so a relative requirements entry like "../backend" fails to resolve. Instead
// we copy the engine source into frontend/vendor at build time and import it
// from there (see api/index.py). The copy is a build artifact (git-ignored) —
// the repository keeps a single source of truth for the engine.

import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // frontend/scripts
const frontend = resolve(here, ".."); // frontend

const candidates = [
  resolve(frontend, "../backend/src/threatlens"), // standard monorepo layout
  resolve(frontend, "backend/src/threatlens"), // if the build root collapses
];

const src = candidates.find(existsSync);
if (!src) {
  console.error(
    "vendor-engine: could not locate backend/src/threatlens. Looked in:\n  " +
      candidates.join("\n  "),
  );
  process.exit(1);
}

const vendorDir = resolve(frontend, "vendor");
const dest = resolve(vendorDir, "threatlens");
mkdirSync(vendorDir, { recursive: true });
cpSync(src, dest, { recursive: true });
console.log(`vendor-engine: copied ${src} -> ${dest}`);
