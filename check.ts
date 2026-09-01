// The gate that runs DURING development, not at kickoff and not at ship.
//
// _system/BUILD_KICKOFF_GATE guards the blank page and
// _system/PRE_SHIP_VERIFICATION_GATE guards the irreversible action. Between
// them is where code is actually written, and there was nothing there. On
// HIGHWATER, eighteen defects shipped across two rounds while both of those
// gates ran clean, because all eighteen were created in that gap.
//
//     bun run check.ts
//
// Wired to a pre-commit hook (git config core.hooksPath .githooks) so it runs
// without anyone having to remember it.
//
// Written in TypeScript and run by bun rather than as check.py, deliberately:
// the vault's drop-in kit is Python, and a Python dependency in the pre-commit
// hook of a TypeScript package is one more thing that can be missing on the
// machine that needs the hook to fire. The structure and the checks are the
// kit's; only the runtime differs.

import { spawnSync } from "node:child_process";
import { join } from "node:path";

const ROOT = import.meta.dirname;
const BIN = join(ROOT, "node_modules", ".bin");
const WIN = process.platform === "win32";

interface Step {
  name: string;
  cmd: string;
  args: string[];
  why: string;
}

const STEPS: Step[] = [
  {
    name: "typecheck",
    cmd: join(BIN, "tsc"),
    args: ["--noEmit"],
    why: "types. cheap, and it catches the shape errors before anything runs.",
  },
  {
    name: "lint",
    cmd: join(BIN, "biome"),
    args: ["check", "./src", "./check.ts", "./checks"],
    why: "formatting and the unused-symbol rules.",
  },
  {
    name: "tests",
    cmd: join(BIN, "vitest"),
    args: ["run", "src/__tests__"],
    why: "the suite. green here means nothing on its own, which is why the next steps exist.",
  },
  {
    name: "test count floor",
    cmd: "bun",
    args: [join(ROOT, "checks", "test_count_floor.ts")],
    why: "a deletion is invisible when an addition lands in the same edit.",
  },
  {
    name: "fail-open lint",
    cmd: "bun",
    args: [join(ROOT, "checks", "failopen_lint.ts")],
    why: "the coercion shapes that have caused a fail-open in this repo.",
  },
  {
    name: "mutations",
    cmd: "bun",
    args: [join(ROOT, "checks", "mutations.ts")],
    why: "reintroduce every bug this repo has shipped and demand the suite notice.",
  },
];

/**
 * What this gate structurally cannot see. Deliberately not empty: a gate that
 * reports zero blind spots is not looking.
 */
const CANNOT_SEE = [
  "whether the thing is worth building",
  "whether the pinned public XRPL node is still operated by who you think, or still up",
  "whether a test asserts the right property, only that it fails when it should",
  "anything a hostile reader would notice and an author would not",
  "whether the published TARBALL matches this working tree. Run `npm pack --dry-run` and read the file list; repo state and package state are different facts",
  "the live network path. `bun scripts/live-check.mjs` exercises it and is NOT run here, because a gate that fails when the wifi drops teaches people to skip the gate",
];

function hookInstalled(): [boolean, string] {
  const r = spawnSync("git", ["config", "core.hooksPath"], { cwd: ROOT, encoding: "utf8" });
  const got = (r.stdout ?? "").trim();
  if (got === ".githooks") return [true, "core.hooksPath = .githooks"];
  if (got === "") {
    return [
      false,
      "not set. this gate is manual-only until you run:\n           git config core.hooksPath .githooks",
    ];
  }
  return [false, `core.hooksPath = ${got}, expected .githooks`];
}

console.log("plugin-xrpl development gate\n");

const [ok, detail] = hookInstalled();
console.log(`[hook] ${ok ? "installed" : "NOT INSTALLED"}: ${detail}\n`);

const failed: string[] = [];

for (const step of STEPS) {
  console.log(`[${step.name}] ${step.why}`);
  const started = Date.now();
  const r = spawnSync(step.cmd, step.args, { cwd: ROOT, encoding: "utf8", shell: WIN });
  const secs = ((Date.now() - started) / 1000).toFixed(1);

  if (r.status === 0) {
    console.log(`    pass (${secs}s)`);
    // Print the step's OWN last line, not just "pass".
    //
    // Discarding it is why a build reported 38 mutation entries and a cold
    // verification pass reported 37, each twice, neither with a command beside
    // it: the harness prints "38 defects reintroduced, 38 caught" and this gate
    // threw it away, so both parties fell back to counting an array by eye. A
    // check whose count nobody sees is a count people re-derive, and eyes
    // miscount.
    const summary = (r.stdout ?? "").trim().split("\n").filter(Boolean).pop();
    if (summary) console.log(`    ${summary}`);
    console.log();
  } else {
    failed.push(step.name);
    console.log(`    FAIL (${secs}s)`);
    const out = `${r.stdout ?? ""}${r.stderr ?? ""}`.trim().split("\n").slice(-25);
    console.log(`    ${out.join("\n    ")}\n`);
  }
}

console.log("=".repeat(70));
console.log("CHANGE GATE  (_system/CHANGE_GATE). Green is not a report.");
console.log("=".repeat(70));
console.log("  change:        <one line. what changed, and why it needed to>");
console.log(
  `  command:       check.ts, ${STEPS.length - failed.length}/${STEPS.length} steps pass`,
);
console.log("  new tests:     <each one, AND what you broke to prove it fails>");
console.log("  removed:       <every test/branch/line deleted, or 'nothing'>");
// The hook status, repeated HERE, beside the verdict.
//
// It is already printed at the top of the run, and then roughly a hundred
// seconds of step output scrolls past it, so by the time GATE GREEN appears the
// warning is off screen and the reader sees a green gate with no idea whether
// anything runs it automatically. HIGHWATER shipped a README and a blog post
// both claiming "runs on a pre-commit hook" for a hook that had never executed
// once.
//
// It does NOT change the exit code, deliberately. A fresh clone has no hook, CI
// has no hooks and needs none, and prepublishOnly runs this gate, so failing
// here would turn a publish red for a reason that has nothing to do with the
// package. A gate that goes red for environmental reasons is a gate people
// learn to skip, which is the same argument that keeps the live check out of it.
console.log(
  `  topology:      pre-commit hook ${
    ok
      ? "INSTALLED, so this gate runs on every commit"
      : "NOT INSTALLED, so NOTHING runs this gate automatically"
  }`,
);
console.log("                 <what else this assumes about its environment,");
console.log("                  and what confirmed the environment agrees>");
console.log("  reviewed by:   <adversarial review brief, or why none>");
console.log("  CANNOT CHECK:");
for (const c of CANNOT_SEE) console.log(`                 - ${c}`);
console.log(`  verdict:       ${failed.length === 0 ? "<GREEN | RED>" : "RED"}`);
console.log();
console.log("  Unfilled fields are unanswered questions, not passed checks.");
console.log();

if (failed.length > 0) {
  console.log(`GATE RED: ${failed.join(", ")}`);
  process.exit(1);
}
console.log("GATE GREEN.");
console.log();
console.log("Green means the checks ran, not that the change is right. For what");
console.log("this cannot see, use a separate agent with a break-it brief and no");
console.log("memory of the build. That is the only mechanism in this vault's");
console.log("history with a 100% hit rate, and it is not automatable, because the");
console.log("point of it is not being the author.");
process.exit(0);
