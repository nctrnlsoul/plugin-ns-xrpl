// A tree-integrity precondition for anything that mutates the working tree.
//
// WHY THIS EXISTS, measured rather than imagined. An interrupted `git commit`
// killed the pre-commit hook, which killed checks/mutations.ts between applying
// a mutation and restoring it. The harness restores inside a `finally`, and a
// `finally` does not survive a hard kill. src/core/response.ts was left holding
//
//     if (false && typeof error === "string" && error !== "") {
//
// which is the guard that turns rippled's HTTP-200-with-an-error-body into
// ACCOUNT_NOT_FOUND. The next commit caught it only because the hook ran.
// `git commit --no-verify`, or any next step that is not the gate, ships it.
//
// The second failure is worse and is why this is a PRECONDITION rather than a
// cleanup. The harness snapshots every target file at startup and calls that
// "the original". Run against an already-poisoned tree it adopts the mutation
// as the baseline, restores TO it, and then grades every guard in the repo
// against a poisoned suite while printing "all files restored byte-identical".
// So the refusal has to happen BEFORE the snapshot, not after.
//
// Pure and exported, per rule 42 and for the same reason as checks/pack_listing.ts:
// the decision lives here where a suite can reach it, and the two scripts only
// wire it up. Every function below either takes its inputs or takes an injected
// reader, so the whole thing is testable without spawning either script.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Bumped whenever the shape changes. An older or newer shape is UNREADABLE. */
export const SENTINEL_VERSION = 1;

/**
 * Repo root, and gitignored.
 *
 * Not under checks/, because biome.json globs checks/**\/*.ts and this is a
 * runtime artifact rather than source. Not tracked, because a committed
 * sentinel would block every clone.
 */
export const SENTINEL_FILE = ".mutation-sentinel.json";

export interface SentinelTarget {
  /** Repo-relative, exactly as the harness names it. */
  readonly file: string;
  /** sha256 of the file's content BEFORE the run touched anything. */
  readonly sha256: string;
}

export interface Sentinel {
  readonly version: number;
  /** Which script is mid-run, so the message can say who to blame. */
  readonly harness: string;
  readonly pid: number;
  readonly startedAt: string;
  readonly targets: readonly SentinelTarget[];
}

/**
 * Three states, and only one of them is "carry on".
 *
 * `unreadable` is deliberately NOT folded into `absent`. A half-written file is
 * the exact artifact a killed process leaves, so treating a parse failure as
 * "no sentinel" would fail open in precisely the case this was written for.
 */
export type SentinelState =
  | { readonly state: "absent" }
  | { readonly state: "present"; readonly sentinel: Sentinel }
  | { readonly state: "unreadable"; readonly why: string };

export function sentinelPath(root: string): string {
  return join(root, SENTINEL_FILE);
}

export function sha256Of(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

export function buildSentinel(
  harness: string,
  pid: number,
  startedAt: string,
  targets: readonly SentinelTarget[],
): Sentinel {
  return { version: SENTINEL_VERSION, harness, pid, startedAt, targets };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Parse a sentinel, refusing every shape that is not exactly right.
 *
 * Never returns `absent`: a string that was handed to this function came from
 * a file that exists, so the only two answers are `present` and `unreadable`.
 */
export function parseSentinel(text: unknown): SentinelState {
  if (typeof text !== "string") return { state: "unreadable", why: "not a string" };

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { state: "unreadable", why: "not valid JSON" };
  }

  if (!isPlainObject(raw)) return { state: "unreadable", why: "not a JSON object" };
  if (raw.version !== SENTINEL_VERSION) {
    return { state: "unreadable", why: `version is ${JSON.stringify(raw.version)}` };
  }
  if (typeof raw.harness !== "string" || raw.harness === "") {
    return { state: "unreadable", why: "no harness name" };
  }
  if (typeof raw.pid !== "number" || !Number.isFinite(raw.pid)) {
    return { state: "unreadable", why: "no usable pid" };
  }
  if (typeof raw.startedAt !== "string" || raw.startedAt === "") {
    return { state: "unreadable", why: "no start time" };
  }
  if (!Array.isArray(raw.targets) || raw.targets.length === 0) {
    // An empty target list cannot detect drift, so it must still BLOCK rather
    // than pass as a well-formed sentinel that finds nothing.
    return { state: "unreadable", why: "no target list" };
  }

  const targets: SentinelTarget[] = [];
  for (const t of raw.targets) {
    if (!isPlainObject(t)) return { state: "unreadable", why: "a target is not an object" };
    if (typeof t.file !== "string" || t.file === "") {
      return { state: "unreadable", why: "a target has no file" };
    }
    if (typeof t.sha256 !== "string" || t.sha256 === "") {
      return { state: "unreadable", why: `no hash recorded for ${t.file}` };
    }
    targets.push({ file: t.file, sha256: t.sha256 });
  }

  return {
    state: "present",
    sentinel: {
      version: raw.version,
      harness: raw.harness,
      pid: raw.pid,
      startedAt: raw.startedAt,
      targets,
    },
  };
}

export function readSentinel(path: string): SentinelState {
  if (!existsSync(path)) return { state: "absent" };
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { state: "unreadable", why: "the file exists and could not be read" };
  }
  return parseSentinel(text);
}

export function writeSentinel(path: string, sentinel: Sentinel): void {
  writeFileSync(path, `${JSON.stringify(sentinel, null, 2)}\n`, "utf8");
}

export function clearSentinel(path: string): void {
  rmSync(path, { force: true });
}

/**
 * Which recorded targets no longer match the content the run started from.
 *
 * `hashOf` returns null for a file that is missing, and a missing target counts
 * as DRIFTED. A file the harness was mid-way through rewriting is the case this
 * exists for, and "I cannot see it" is not "it is fine".
 */
export function driftedTargets(
  sentinel: Sentinel,
  hashOf: (file: string) => string | null,
): string[] {
  const drifted: string[] = [];
  for (const t of sentinel.targets) {
    if (hashOf(t.file) !== t.sha256) drifted.push(t.file);
  }
  return drifted;
}

/**
 * The sentinel may be removed ONLY when the restore was verified byte-identical.
 *
 * Named rather than inlined so there is one line to read, one line to break, and
 * one line for checks/mutations.ts to target. Clearing after a failed restore
 * hands the next run a poisoned tree with nothing left to warn it.
 */
export function mayClearSentinel(dirtyFileCount: number): boolean {
  return dirtyFileCount === 0;
}

/** The refusal a human reads. Says which run left it, what drifted, and what to do. */
export function describeStaleSentinel(
  sentinel: Sentinel,
  drifted: readonly string[],
  path: string,
): string {
  const lines: string[] = [
    "TREE INTEGRITY: a mutation run did not finish, so this tree may not be yours.",
    "",
    `  left by:     ${sentinel.harness}`,
    `  pid:         ${sentinel.pid}`,
    `  started:     ${sentinel.startedAt}`,
    `  sentinel:    ${path}`,
    `  watching:    ${sentinel.targets.length} file(s) that run is allowed to rewrite`,
    "",
  ];

  if (drifted.length === 0) {
    lines.push(
      "  Every watched file still matches the content that run started from, so the",
      "  tree LOOKS intact. That is not an all clear: the run was killed, and this",
      "  check only compares the files it recorded.",
    );
  } else {
    lines.push(
      `  ${drifted.length} file(s) DIFFER from the content that run started from. Each one may`,
      "  still be carrying a mutation:",
      "",
    );
    for (const f of drifted) lines.push(`    - ${f} differs`);
  }

  lines.push(
    "",
    "  What to do, in this order:",
    `    1. Read the diff of each file listed above. A mutation looks like a guard`,
    "       turned off, for example `if (false && ...)`.",
    "    2. Restore it. If the file had no uncommitted work, `git checkout -- <file>`",
    "       is exact. If it did, edit the mutation out by hand: do NOT discard the",
    "       work, and do not let anything restore it for you.",
    `    3. Delete ${path}, then run the gate again.`,
    "",
    "  This check refuses rather than repairing, because a file with uncommitted",
    "  work in it is not something a check may overwrite.",
  );

  return lines.join("\n");
}

/**
 * The one call both check.ts and checks/mutations.ts make, first, before
 * anything else. Returns the refusal to print, or null to carry on.
 */
export function staleSentinelRefusal(root: string): string | null {
  const path = sentinelPath(root);
  const state = readSentinel(path);

  if (state.state === "absent") return null;

  if (state.state === "unreadable") {
    return [
      "TREE INTEGRITY: a mutation-run sentinel exists and is unreadable, so this",
      "tree may not be yours.",
      "",
      `  sentinel:    ${path}`,
      `  why:         ${state.why}`,
      "",
      "  A half-written sentinel is what a killed process leaves behind, so this is",
      "  treated as an unfinished run rather than as no run at all.",
      "",
      "  What to do:",
      "    1. Check `git status` and the diff of every file under src/ and checks/.",
      "    2. Restore anything carrying a mutation, by hand if it holds uncommitted",
      "       work.",
      `    3. Delete ${path}, then run the gate again.`,
    ].join("\n");
  }

  const drifted = driftedTargets(state.sentinel, (file) => {
    const abs = join(root, file);
    if (!existsSync(abs)) return null;
    try {
      return sha256Of(readFileSync(abs, "utf8"));
    } catch {
      return null;
    }
  });

  return describeStaleSentinel(state.sentinel, drifted, path);
}
