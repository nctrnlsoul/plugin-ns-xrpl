// A test-count floor.
//
// Rule 35 makes this load-bearing rather than decorative: a suite that silently
// stops loading a file otherwise passes vacuously, and a deletion is invisible
// when an addition lands in the same edit.
//
// It counts by RUNNING the suite and reading the number it reports, not by
// grepping for `it(` in the source. Grepping counts tests that exist; running
// counts tests that executed, and the failure this guards against is a file that
// stopped being loaded at all.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");

const floorFile = readFileSync(join(ROOT, "checks", "test_count_floor.txt"), "utf8");
const firstLine = floorFile.split("\n")[0]?.trim() ?? "";
const floor = Number.parseInt(firstLine, 10);

if (!Number.isInteger(floor) || floor <= 0) {
  console.log(
    `test count floor: the floor file does not start with a positive integer (${JSON.stringify(firstLine)})`,
  );
  process.exit(1);
}

const r = spawnSync(join(ROOT, "node_modules", ".bin", "vitest"), ["run", "src/__tests__"], {
  cwd: ROOT,
  encoding: "utf8",
  shell: process.platform === "win32",
});
const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;

// vitest prints e.g. "Tests  116 passed (116)". The number in parentheses is the
// total, which is the one that matters: passed alone would let a skipped file
// look healthy.
const match = out.match(/Tests\s+.*?\((\d+)\)/);
if (!match?.[1]) {
  console.log("test count floor: could not read a test total from the runner output.");
  console.log("This is a FAILURE, not a skip: an unreadable count is an uncounted suite.");
  console.log(out.split("\n").slice(-15).join("\n"));
  process.exit(1);
}

const actual = Number.parseInt(match[1], 10);

if (actual < floor) {
  console.log(`test count floor: ${actual} tests, floor is ${floor}. ${floor - actual} MISSING.`);
  console.log("Lowering the floor is allowed. Doing it silently is not: edit");
  console.log("checks/test_count_floor.txt and say why in the commit message.");
  process.exit(1);
}

console.log(`test count floor: ${actual} tests, floor ${floor}`);
process.exit(0);
