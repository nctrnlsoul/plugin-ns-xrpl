// Repo state and package state are different facts.
//
// Rule 85's second half: having deleted something, verify it is absent from the
// published TARBALL, not merely from the repo. And the inverse, which is what
// actually bit here: verify the things package.json PROMISES are present.
//
// Found by reading an `npm pack --dry-run` file list rather than by trusting a
// build that printed "Build complete!": declarations were emitting to
// dist/src/index.d.ts while package.json declared dist/index.d.ts, so the
// tarball was complete, the build was green, and every consumer would have got
// zero types.
//
// TWO trees are measured here, and they are different facts.
//
// D1, and it is the reason this file was restructured. The original ran the
// build FIRST, and build.ts deletes dist. So the guard cleaned its own subject
// before measuring it, and could not fail on the input it existed to catch: it
// printed "no frontend, no build metadata, nothing secret-shaped" and exited 0
// against a tree where `npm pack --dry-run` listed 163.4 kB of
// dist/tsconfig.tsbuildinfo, 57% of the unpacked package.
//
// So phase 1 measures the tree AS HANDED, which is the tree `npm publish` would
// actually ship, because npm rebuilds nothing on its own. Phase 2 rebuilds and
// measures again, which is the original check and still catches a stale or
// absent dist. Neither replaces the other.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { scanPackListing } from "./pack_listing.ts";

const ROOT = join(import.meta.dirname, "..");
const WIN = process.platform === "win32";

const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

/** Read the real tarball listing rather than assuming `files` behaves. */
function packListing(): string {
  const pack = spawnSync("npm", ["pack", "--dry-run"], { cwd: ROOT, encoding: "utf8", shell: WIN });
  return `${pack.stdout ?? ""}${pack.stderr ?? ""}`;
}

// ---------------------------------------------------------------------------
// PHASE 1. The WORKING TREE, exactly as handed over. Nothing is rebuilt first.
// ---------------------------------------------------------------------------
if (existsSync(join(ROOT, "dist"))) {
  const asHanded = scanPackListing(packListing(), "as handed");
  if (asHanded.length > 0) {
    console.log("package entries: the WORKING TREE would publish files that must not ship.\n");
    for (const p of asHanded) console.log(`  - ${p}`);
    console.log("\nThis is the tree as handed over, measured BEFORE any rebuild, because that");
    console.log("is the tree npm publish would ship. Run `bun run build` and check again.");
    process.exit(1);
  }
  console.log("package entries: the tree as handed is clean (measured before any rebuild)");
} else {
  console.log("package entries: no dist/ yet, so the as-handed tree has nothing to be stale");
}

// ---------------------------------------------------------------------------
// PHASE 2. Rebuild, then check what package.json PROMISES actually exists.
// ---------------------------------------------------------------------------
console.log("package entries: building, so the rest cannot pass on a stale dist");
const build = spawnSync("bun", ["run", "build"], { cwd: ROOT, encoding: "utf8", shell: WIN });
if (build.status !== 0) {
  console.log("package entries: the build FAILED, so there is nothing to verify.");
  console.log(
    `${build.stdout ?? ""}${build.stderr ?? ""}`.trim().split("\n").slice(-15).join("\n"),
  );
  process.exit(1);
}

const problems: string[] = [];

/** Every path package.json promises a consumer. */
const promised: Array<[string, unknown]> = [
  ["main", pkg.main],
  ["module", pkg.module],
  ["types", pkg.types],
  ["exports['.'].import.types", pkg.exports?.["."]?.import?.types],
  ["exports['.'].import.default", pkg.exports?.["."]?.import?.default],
];

for (const [label, value] of promised) {
  if (typeof value !== "string") {
    problems.push(`${label} is not a string path`);
    continue;
  }
  const rel = value.replace(/^\.\//, "");
  if (!existsSync(join(ROOT, rel))) {
    problems.push(`${label} promises "${value}" and that file DOES NOT EXIST after a build`);
  }
}

// Now the freshly built tree, through the same scanner phase 1 used. A term the
// build itself emits would be invisible to phase 1 alone.
const listing = packListing();
problems.push(...scanPackListing(listing, "after a fresh build"));

const files = (listing.match(/^npm notice total files: (\d+)/im) ?? [])[1];
const size = (listing.match(/^npm notice unpacked size: (.+)$/im) ?? [])[1];

if (problems.length > 0) {
  console.log(`\npackage entries: ${problems.length} problem(s) with the PUBLISHED package\n`);
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}

console.log(`package entries: every declared entry exists; ${files} files, ${size} unpacked`);
console.log("package entries: no frontend, no build metadata, nothing secret-shaped");
console.log("package entries: BOTH the tree as handed and the freshly built tree were measured");
process.exit(0);
