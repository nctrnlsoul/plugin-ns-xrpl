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
// This builds first, so it can never pass by inspecting a stale or absent dist.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const WIN = process.platform === "win32";

const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

console.log("package entries: building first, so this cannot inspect a stale dist");
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

// Read the real tarball listing rather than assuming `files` behaves.
const pack = spawnSync("npm", ["pack", "--dry-run"], { cwd: ROOT, encoding: "utf8", shell: WIN });
const listing = `${pack.stdout ?? ""}${pack.stderr ?? ""}`;

// The deleted frontend organism must be absent from the PACKAGE, not just the
// repo. Rule 85: dead code answers audits on behalf of live code.
const BANNED = ["react", "vite", "tailwind", "postcss", "frontend", "index.html", "tanstack"];
for (const term of BANNED) {
  const re = new RegExp(`^npm notice.*${term}`, "im");
  if (re.test(listing)) problems.push(`the tarball still contains something matching "${term}"`);
}

// Build metadata is not a deliverable.
for (const junk of ["tsbuildinfo", ".env", "node_modules"]) {
  const re = new RegExp(`^npm notice.*${junk.replace(".", "\\.")}`, "im");
  if (re.test(listing)) problems.push(`the tarball ships "${junk}", which is not a deliverable`);
}

// Nothing that could carry a secret.
for (const secretish of [".npmrc", "id_rsa", ".pem", ".key"]) {
  const re = new RegExp(`^npm notice.*${secretish.replace(".", "\\.")}`, "im");
  if (re.test(listing)) problems.push(`the tarball ships "${secretish}"`);
}

const files = (listing.match(/^npm notice total files: (\d+)/im) ?? [])[1];
const size = (listing.match(/^npm notice unpacked size: (.+)$/im) ?? [])[1];

if (problems.length > 0) {
  console.log(`\npackage entries: ${problems.length} problem(s) with the PUBLISHED package\n`);
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}

console.log(`package entries: every declared entry exists; ${files} files, ${size} unpacked`);
console.log("package entries: no frontend, no build metadata, nothing secret-shaped");
process.exit(0);
