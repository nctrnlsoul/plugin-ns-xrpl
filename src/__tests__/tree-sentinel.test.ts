// The tree-integrity precondition, written BEFORE checks/tree_sentinel.ts.
//
// The hazard is measured, not hypothetical. An interrupted `git commit` killed
// the pre-commit hook mid-run, which killed checks/mutations.ts between applying
// a mutation and restoring it. Its restore sits in a `finally`, and a `finally`
// does not survive a hard kill. The tree was left carrying
//
//     if (false && typeof error === "string" && error !== "") {
//
// in src/core/response.ts: the guard that turns rippled's HTTP-200-with-an-
// error-body into ACCOUNT_NOT_FOUND. The next `git commit` caught it only
// because the hook ran. A `--no-verify`, or any next step that is not the gate,
// and it ships.
//
// Worse, the harness snapshots each target file as "the original" at startup.
// Run against an already-poisoned tree it would adopt the mutation as the
// baseline, restore TO it, and grade 81 guards against it. So the harness has
// to refuse BEFORE it snapshots, which is why the precondition is a value both
// scripts read rather than a step either of them runs.
//
// Everything below tests the shared module. Neither check.ts nor
// checks/mutations.ts is ever spawned from here: both run the suite, so
// spawning either one from inside the suite recurses, and if the guard under
// test were the mutated thing it would recurse without bound. The wiring is
// asserted structurally instead, and that limit is stated in the commit.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildSentinel,
  clearSentinel,
  describeStaleSentinel,
  driftedTargets,
  mayClearSentinel,
  parseSentinel,
  readSentinel,
  SENTINEL_FILE,
  SENTINEL_VERSION,
  sentinelPath,
  staleSentinelRefusal,
  writeSentinel,
} from "../../checks/tree_sentinel.ts";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

/** A throwaway root, so no test can touch the real sentinel. */
function tempRoot(): string {
  return mkdtempSync(join(tmpdir(), "xrpl-sentinel-"));
}

const targetsFor = (root: string, files: Record<string, string>) =>
  Object.entries(files).map(([file, body]) => {
    writeFileSync(join(root, file), body, "utf8");
    return { file, sha256: sha(body) };
  });

describe("the sentinel survives a round trip and is a value, not a flag", () => {
  it("writes, reads back identically, and clears", () => {
    const root = tempRoot();
    try {
      const targets = targetsFor(root, { "a.ts": "one", "b.ts": "two" });
      const s = buildSentinel("checks/mutations.ts", 4242, "2026-09-01T11:14:16.000Z", targets);
      const path = sentinelPath(root);
      expect(path.endsWith(SENTINEL_FILE), path).toBe(true);

      expect(readSentinel(path).state, "nothing written yet").toBe("absent");
      writeSentinel(path, s);

      const back = readSentinel(path);
      expect(back.state).toBe("present");
      if (back.state === "present") {
        expect(back.sentinel.harness).toBe("checks/mutations.ts");
        expect(back.sentinel.pid).toBe(4242);
        expect(back.sentinel.startedAt).toBe("2026-09-01T11:14:16.000Z");
        expect(back.sentinel.version).toBe(SENTINEL_VERSION);
        expect(back.sentinel.targets.map((t) => t.file)).toEqual(["a.ts", "b.ts"]);
      }

      clearSentinel(path);
      expect(existsSync(path), "clearing must remove the file").toBe(false);
      expect(readSentinel(path).state).toBe("absent");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("an UNREADABLE sentinel BLOCKS, and is never reported as absent", () => {
    // The fail-closed half, and the one that matters. A half-written sentinel
    // from a killed process is exactly the state this exists to catch, so a
    // parse failure must be at least as blocking as a valid sentinel. Reading
    // it as "absent" would be the fail-open shape this repo bans everywhere
    // else, arriving through a JSON.parse instead of a `?? []`.
    const good = buildSentinel("checks/mutations.ts", 1, "2026-09-01T00:00:00.000Z", [
      { file: "a.ts", sha256: sha("one") },
    ]);
    const junk: unknown[] = [
      "",
      "   ",
      "{",
      '{"version":1,',
      "null",
      "[]",
      "42",
      '"a string"',
      "{}",
      JSON.stringify({ ...good, version: SENTINEL_VERSION + 1 }),
      JSON.stringify({ ...good, version: "1" }),
      JSON.stringify({ ...good, harness: "" }),
      JSON.stringify({ ...good, pid: "4242" }),
      JSON.stringify({ ...good, startedAt: 0 }),
      JSON.stringify({ ...good, targets: "a.ts" }),
      JSON.stringify({ ...good, targets: [] }),
      JSON.stringify({ ...good, targets: [{ file: "a.ts" }] }),
      JSON.stringify({ ...good, targets: [{ sha256: sha("one") }] }),
      JSON.stringify({ ...good, targets: [{ file: 1, sha256: sha("one") }] }),
      null,
      undefined,
      42,
      {},
    ];
    for (const bad of junk) {
      const got = parseSentinel(bad);
      expect(got.state, `${JSON.stringify(bad)} must not parse`).toBe("unreadable");
      expect(got.state, `${JSON.stringify(bad)} must never read as absent`).not.toBe("absent");
    }
    // The positive control. If nothing parses, the assertions above are empty.
    expect(parseSentinel(JSON.stringify(good)).state).toBe("present");
  });

  it("a MISSING file is the only thing that counts as absent", () => {
    const root = tempRoot();
    try {
      const path = sentinelPath(root);
      expect(readSentinel(path).state).toBe("absent");
      writeFileSync(path, "{ this is not json", "utf8");
      expect(readSentinel(path).state, "present but corrupt is not absent").toBe("unreadable");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("an EMPTY sentinel file is unreadable, not absent", () => {
    // Zero bytes is not a hypothetical shape. writeFileSync truncates first and
    // then writes, so a process killed between those two leaves exactly this,
    // and it is the same kill this whole module exists for. A source-side
    // enumeration found that nothing pinned it: readSentinel could be made to
    // treat an empty file as "no sentinel" and the entire suite stayed green.
    const root = tempRoot();
    try {
      const path = sentinelPath(root);
      writeFileSync(path, "", "utf8");
      expect(readSentinel(path).state, "zero bytes is a killed write, not no run").toBe(
        "unreadable",
      );
      writeFileSync(path, "   \n\t \n", "utf8");
      expect(readSentinel(path).state, "whitespace only is the same case").toBe("unreadable");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("a sentinel that EXISTS and cannot be read is unreadable, not absent", () => {
    // readSentinel's catch branch, which had no test at all. Reached here by
    // putting a directory at the sentinel path: existsSync says yes and
    // readFileSync throws. "I cannot see it" is not "it is fine", and folding
    // this into `absent` is a fail-open arriving through a catch rather than
    // through a `?? []`.
    const root = tempRoot();
    try {
      const path = sentinelPath(root);
      mkdirSync(path);
      const got = readSentinel(path);
      expect(got.state, "unreadable, and never absent").toBe("unreadable");
      expect(got.state, "must not read as absent").not.toBe("absent");
      if (got.state === "unreadable") {
        expect(got.why, "and it must say WHY, not just refuse").toMatch(/could not be read/i);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("drift detection names the poisoned files and nothing else", () => {
  const s = buildSentinel("checks/mutations.ts", 1, "2026-09-01T00:00:00.000Z", [
    { file: "a.ts", sha256: sha("one") },
    { file: "b.ts", sha256: sha("two") },
    { file: "c.ts", sha256: sha("three") },
  ]);

  it("names exactly the targets whose content changed", () => {
    const now = new Map([
      ["a.ts", sha("one")],
      ["b.ts", sha("CHANGED")],
      ["c.ts", sha("three")],
    ]);
    expect(driftedTargets(s, (f) => now.get(f) ?? null)).toEqual(["b.ts"]);
  });

  it("THRESHOLD: a single drifted file is reported, not swallowed", () => {
    // The smallest case that must trip it is one. The measured incident was
    // exactly one file.
    const now = new Map([
      ["a.ts", sha("one")],
      ["b.ts", sha("two")],
      ["c.ts", sha("POISONED")],
    ]);
    const drifted = driftedTargets(s, (f) => now.get(f) ?? null);
    expect(drifted).toHaveLength(1);
    expect(drifted).toEqual(["c.ts"]);
  });

  it("a target that has VANISHED counts as drifted, never as intact", () => {
    const now = new Map([["a.ts", sha("one")]]);
    expect(driftedTargets(s, (f) => now.get(f) ?? null)).toEqual(["b.ts", "c.ts"]);
  });

  it("reports nothing when every target matches, so the finding is signal", () => {
    // The negative control. A detector that always fires satisfies all three
    // assertions above and means nothing.
    const now = new Map([
      ["a.ts", sha("one")],
      ["b.ts", sha("two")],
      ["c.ts", sha("three")],
    ]);
    expect(driftedTargets(s, (f) => now.get(f) ?? null)).toEqual([]);
  });
});

describe("the refusal says WHICH run left it and WHAT TO DO", () => {
  const s = buildSentinel("checks/mutations.ts", 31337, "2026-09-01T11:14:16.000Z", [
    { file: "src/core/response.ts", sha256: sha("pristine") },
    { file: "src/core/render.ts", sha256: sha("also pristine") },
  ]);

  it("names the harness, the pid, the start time and the sentinel path", () => {
    const msg = describeStaleSentinel(s, ["src/core/response.ts"], "/repo/.mutation-sentinel.json");
    expect(msg, "which harness").toContain("checks/mutations.ts");
    expect(msg, "which process").toContain("31337");
    expect(msg, "when it started").toContain("2026-09-01T11:14:16.000Z");
    expect(msg, "what to delete once the tree is clean").toContain("/repo/.mutation-sentinel.json");
    expect(msg.trim().length, "an empty refusal is an invisible refusal").toBeGreaterThan(0);
  });

  it("THRESHOLD: names the one drifted file, and says it is one", () => {
    const msg = describeStaleSentinel(s, ["src/core/response.ts"], "/repo/.mutation-sentinel.json");
    expect(msg).toContain("src/core/response.ts");
    expect(msg, "the count must be stated, at one").toMatch(/\b1 (file|of)\b/);
    expect(msg, "an intact file must not be listed as drifted").not.toContain(
      "src/core/render.ts differs",
    );
  });

  it("still REFUSES when nothing drifted, and does not read as an all-clear", () => {
    // A run killed before it applied anything leaves a sentinel over a clean
    // tree. That is still an unfinished run, and the honest thing is to say the
    // tree looks intact and refuse anyway rather than to imply it was checked.
    const msg = describeStaleSentinel(s, [], "/repo/.mutation-sentinel.json");
    expect(msg.trim().length).toBeGreaterThan(0);
    expect(msg, "it must say the run was interrupted").toMatch(/did not finish|unfinished/i);
    // Asserting the POSITIVE property, not the absence of a phrase. The first
    // version of this test banned the words "all clear", which the message
    // trips by correctly saying "that is not an all clear". A negative
    // assertion about wording is satisfied by rephrasing; what must hold is
    // that no VERDICT clearing the tree appears.
    expect(msg, "no verdict may clear the tree").not.toMatch(
      /\b(GREEN|safe to (?:proceed|continue)|nothing to do|tree is clean)\b/i,
    );
    expect(msg, "and it must still tell the reader what to do").toMatch(/What to do/);
  });

  it("never tells anyone to bypass the gate", () => {
    // The one instruction this message must never carry. It is read by someone
    // who is blocked and in a hurry.
    for (const drifted of [[], ["src/core/response.ts"]]) {
      const msg = describeStaleSentinel(s, drifted, "/repo/.mutation-sentinel.json");
      expect(msg, "must not teach --no-verify").not.toMatch(/--no-verify/);
    }
  });
});

describe("the sentinel is cleared ONLY when the restore verified clean", () => {
  it("clears at zero dirty files and at no other count", () => {
    // The rule the incident turns on. Clearing after a failed restore would
    // hand the next run a poisoned tree with nothing to warn it.
    expect(mayClearSentinel(0), "a verified-clean restore may clear it").toBe(true);
    for (const dirty of [1, 2, 14]) {
      expect(mayClearSentinel(dirty), `${dirty} dirty file(s) must keep the sentinel`).toBe(false);
    }
  });
});

describe("staleSentinelRefusal is what both scripts actually call", () => {
  it("returns null on a clean root, so the gate is not blocked for nothing", () => {
    const root = tempRoot();
    try {
      expect(staleSentinelRefusal(root)).toBeNull();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("returns a refusal naming the drifted file when a run was interrupted", () => {
    const root = tempRoot();
    try {
      const targets = targetsFor(root, { "clean.ts": "pristine", "poisoned.ts": "pristine" });
      writeSentinel(
        sentinelPath(root),
        buildSentinel("checks/mutations.ts", 31337, "2026-09-01T11:14:16.000Z", targets),
      );
      // Reproduce the incident: one target left carrying a mutation.
      writeFileSync(join(root, "poisoned.ts"), "if (false && pristine) {}", "utf8");

      const msg = staleSentinelRefusal(root);
      expect(msg, "an interrupted run must block").not.toBeNull();
      expect(msg ?? "").toContain("poisoned.ts");
      expect(msg ?? "").toContain("31337");
      expect(msg ?? "", "the intact file must not be blamed").not.toMatch(
        /clean\.ts\b[^\n]*differs/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("REFUSES when a run was killed and nothing drifted", () => {
    // The same property as "still REFUSES when nothing drifted" above, asserted
    // on the function both scripts CALL rather than on the message builder it
    // delegates to. That gap was real: a source-side enumeration made
    // staleSentinelRefusal return null whenever the drift list came back empty,
    // and the whole suite stayed green, because the only assertion of this
    // property was one layer down on describeStaleSentinel.
    //
    // A run killed before it wrote its first mutation, or killed after the
    // restore and before the sentinel came up, leaves exactly this state. It is
    // still an unfinished run.
    const root = tempRoot();
    try {
      const targets = targetsFor(root, { "a.ts": "one", "b.ts": "two" });
      writeSentinel(
        sentinelPath(root),
        buildSentinel("checks/mutations.ts", 31337, "2026-09-01T11:14:16.000Z", targets),
      );
      const msg = staleSentinelRefusal(root);
      expect(msg, "an unfinished run is unfinished whether or not a file drifted").not.toBeNull();
      expect(msg ?? "", "it must say the run was interrupted").toMatch(
        /did not finish|unfinished/i,
      );
      expect(msg ?? "", "and name the run, so this is not a generic refusal").toContain("31337");
      expect(msg ?? "", "no verdict may clear the tree").not.toMatch(
        /\b(GREEN|safe to (?:proceed|continue)|nothing to do|tree is clean)\b/i,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("BLOCKS on a corrupt sentinel file rather than running", () => {
    const root = tempRoot();
    try {
      writeFileSync(sentinelPath(root), '{"version":1,"harn', "utf8");
      const msg = staleSentinelRefusal(root);
      expect(msg, "a half-written sentinel is the exact killed-process case").not.toBeNull();
      expect(msg ?? "").toMatch(/unreadable|could not be read/i);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("both scripts run the precondition before they touch anything", () => {
  // Structural, and deliberately so. Spawning check.ts or checks/mutations.ts
  // from here would run the suite from inside the suite, and under the mutation
  // that removes this very guard it would recurse without bound. So this
  // asserts the call site and its POSITION rather than executing it.
  const ROOT = join(import.meta.dirname, "..", "..");
  const read = (rel: string) => readFileSync(join(ROOT, rel), "utf8");

  /** Words after which a `/` opens a regular expression instead of dividing. */
  const REGEX_AFTER_KEYWORD = new Set([
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
  ]);

  /**
   * Punctuation after which a `/` opens a regular expression.
   *
   * `)` and `]` are deliberately absent: they close a value, so `(a + b) / c`
   * divides. Everything here closes nothing.
   */
  const REGEX_AFTER_PUNCTUATION = "([{,;:=!&|?+-*%~^<>";

  /**
   * Blank every comment, string literal and REGULAR EXPRESSION literal, keeping
   * length and line breaks so indices still line up with the original.
   *
   * This is not tidiness. checks/mutations.ts is a table of source fragments
   * QUOTED AS DATA, so the moment the wiring below got its own mutation entries
   * the file began containing the literal text `if (staleTree !== null) {`
   * inside a `find:` string, ABOVE the real wiring. The first version of these
   * assertions matched that quotation, walked its braces, and failed. It could
   * equally have passed against a file whose wiring had been deleted, as long
   * as an entry still quoted it.
   *
   * An assertion about CODE has to be made against code.
   *
   * Regex literals were the hole a cold pass walked through. Blanking comments
   * and strings and stopping there left a THIRD way to write the wiring down
   * without running it, and the file this guards is a table of source fragments,
   * which is one edit away from being a table of patterns. Measured, not
   * imagined: check.ts with its six live lines replaced by two regexes quoting
   * them left the whole suite green and the gate ran five steps over a poisoned
   * tree instead of refusing.
   *
   * Telling a regex from a division needs the previous token, which is why
   * `regexAllowed` is carried rather than inferred from the output: a blanked
   * string is spaces, so looking backwards would see whatever preceded it.
   * Ambiguity resolves to REGEX, because guessing regex only blanks code and
   * turns this assertion red, and guessing division is the fail-open that let a
   * quoted guard read as a live one.
   */
  const codeOnly = (src: string): string => {
    let out = "";
    let i = 0;
    let regexAllowed = true;
    let word = "";

    /** A word just ended, so decide what a `/` after it would mean. */
    const endWord = () => {
      if (word !== "") {
        regexAllowed = REGEX_AFTER_KEYWORD.has(word);
        word = "";
      }
    };

    while (i < src.length) {
      const two = src.slice(i, i + 2);
      if (two === "//") {
        while (i < src.length && src[i] !== "\n") {
          out += " ";
          i++;
        }
        continue;
      }
      if (two === "/*") {
        while (i < src.length && src.slice(i, i + 2) !== "*/") {
          out += src[i] === "\n" ? "\n" : " ";
          i++;
        }
        out += "  ";
        i += 2;
        continue;
      }
      const c = src[i];
      if (c === '"' || c === "'" || c === "`") {
        endWord();
        out += " ";
        i++;
        while (i < src.length) {
          if (src[i] === "\\") {
            out += "  ";
            i += 2;
            continue;
          }
          if (src[i] === c) {
            out += " ";
            i++;
            break;
          }
          out += src[i] === "\n" ? "\n" : " ";
          i++;
        }
        regexAllowed = false;
        continue;
      }
      if (c === "/") {
        endWord();
        if (regexAllowed) {
          out += " ";
          i++;
          // A `/` inside a character class does not close the literal, and a
          // literal cannot span a line. Hitting a newline means the guess was
          // wrong, and stopping there blanks only that line.
          let inClass = false;
          while (i < src.length) {
            const ch = src[i];
            if (ch === "\\") {
              out += "  ";
              i += 2;
              continue;
            }
            if (ch === "\n") break;
            if (ch === "[") inClass = true;
            else if (ch === "]") inClass = false;
            else if (ch === "/" && !inClass) {
              out += " ";
              i++;
              break;
            }
            out += " ";
            i++;
          }
          regexAllowed = false;
          continue;
        }
        out += c;
        i++;
        regexAllowed = true;
        continue;
      }
      if (/[A-Za-z0-9_$]/.test(c ?? "")) {
        word += c;
      } else if (!/\s/.test(c ?? "")) {
        endWord();
        regexAllowed = REGEX_AFTER_PUNCTUATION.includes(c ?? "");
      } else {
        endWord();
      }
      out += c;
      i++;
    }
    return out;
  };

  /**
   * Brace depth at `index`, over codeOnly output. Zero is module scope.
   *
   * The reason this exists is measured. The guard was moved into an exported
   * function with no call site: every line present, correct, in the right order
   * and above the first step, and it never ran. tsc, biome and all 276 tests
   * stayed green and the gate did not refuse a poisoned tree. "Present in the
   * file" and "runs when the file runs" are different claims.
   */
  const depthAt = (src: string, index: number): number => {
    let depth = 0;
    for (let i = 0; i < index; i++) {
      if (src[i] === "{") depth++;
      else if (src[i] === "}") depth--;
    }
    return depth;
  };

  /** The one shape that counts as calling the precondition. */
  const CALL_BINDING = /(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*staleSentinelRefusal\(/;

  /**
   * Where the MODULE-SCOPE call actually is, in code, or -1.
   *
   * Anchoring on the first occurrence anywhere in the file is what the ordering
   * assertions used to do, and checks/mutations.ts mentions the call in a
   * comment at line 810 and makes it at line 902. So "before the snapshot" was
   * being proved by prose, and stayed true with the real call moved anywhere.
   */
  const preconditionCallIndex = (raw: string): number => {
    const src = codeOnly(raw);
    const m = src.match(CALL_BINDING);
    if (!m || m.index === undefined) return -1;
    return depthAt(src, m.index) === 0 ? m.index : -1;
  };

  /** Where a code anchor is, ignoring comments, strings and regex literals. */
  const codeIndexOf = (raw: string, needle: string): number => codeOnly(raw).indexOf(needle);

  /**
   * The brace-matched block starting at the first `{` at or after `from`.
   *
   * Counting braces rather than regexing to a closing line, because "the exit
   * is somewhere later in the file" is exactly the thing this must not accept.
   * Run over codeOnly output, so a brace inside a string cannot skew the count.
   */
  const blockAfter = (src: string, from: number): string | null => {
    const open = src.indexOf("{", from);
    if (open < 0) return null;
    let depth = 0;
    for (let i = open; i < src.length; i++) {
      if (src[i] === "{") depth++;
      else if (src[i] === "}") {
        depth--;
        if (depth === 0) return src.slice(open, i + 1);
      }
    }
    return null;
  };

  /**
   * The refusal must be BOUND, AT MODULE SCOPE, TESTED and ACTED ON.
   *
   * The first version of these tests asserted only that the call existed and
   * came before the snapshot. `staleSentinelRefusal(ROOT);` on a line of its
   * own satisfies both and refuses nothing at all: the guard runs, computes the
   * right answer, and drops it. That is the shape a check like this fails in,
   * and it is invisible to "does the call exist".
   *
   * The second version added binding, polarity and the exit, and was defeated
   * by moving all four into a function nobody calls.
   */
  const actsOnTheRefusal = (raw: string, label: string) => {
    const src = codeOnly(raw);

    // 1. BOUND. A bare call statement cannot match this.
    const bind = src.match(CALL_BINDING);
    expect(bind, `${label} must BIND the refusal, not discard it`).not.toBeNull();
    const name = bind?.[1] ?? "";
    expect(name, `${label} must bind to a name`).not.toBe("");

    // 1b. AT MODULE SCOPE, so running the file runs the guard. Inside a
    //     function it is a definition, not a precondition, and the difference
    //     is invisible to every other check in this package: tsc, biome and the
    //     full suite all stayed green over an exported guard with no call site.
    expect(
      depthAt(src, bind?.index ?? 0),
      `${label} must call the precondition at MODULE SCOPE, not inside a function`,
    ).toBe(0);

    // 2. TESTED, and with the polarity that refuses when there IS a refusal.
    //    `if (x === null)` binds, tests and exits, and would block a clean tree
    //    while sailing straight past a poisoned one. Pinned by form, not by
    //    execution, and that limit is real.
    const cond = new RegExp(`if\\s*\\(\\s*${name}\\s*(?:!==?\\s*null|\\)|&&)`);
    const tested = src.search(cond);
    expect(tested, `${label} must TEST ${name}, and must not invert the test`).toBeGreaterThan(-1);
    expect(tested, `${label} must test ${name} after binding it`).toBeGreaterThan(
      bind?.index ?? -1,
    );
    expect(depthAt(src, tested), `${label} must TEST it at module scope too`).toBe(0);

    // 3. EXITS NON-ZERO, inside the block that did the testing. Not later, not
    //    somewhere else in the file.
    const block = blockAfter(src, tested);
    expect(block, `${label} the tested block must be matchable`).not.toBeNull();
    expect(
      (block ?? "").length,
      `${label} matched block must be a block, not the rest of the file`,
    ).toBeLessThan(1200);
    expect(block ?? "", `${label} must exit non-zero INSIDE the block that tested it`).toContain(
      "process.exit(1)",
    );
  };

  it("check.ts refuses before it runs a single step", () => {
    // Every index here comes from preconditionCallIndex and codeIndexOf, which
    // read code. Anchoring on the first mention anywhere in the file was how
    // the sibling test below was being satisfied by a comment.
    const raw = read("check.ts");
    const call = preconditionCallIndex(raw);
    expect(call, "check.ts must CALL the precondition, at module scope").toBeGreaterThan(-1);
    expect(raw, "and import it").toMatch(/from "\.\/checks\/tree_sentinel\.ts"/);

    const firstStepRun = codeIndexOf(raw, "for (const step of STEPS)");
    expect(firstStepRun, "the step loop must exist for this to mean anything").toBeGreaterThan(-1);
    expect(call, "the refusal must come BEFORE the first step runs").toBeLessThan(firstStepRun);
  });

  it("checks/mutations.ts refuses before it snapshots a single file", () => {
    // The ordering that actually matters. Snapshotting first would adopt a
    // poisoned file as "the original" and restore to it.
    //
    // This file is why the anchors below have to be code. It mentions the call
    // in a comment at line 810 and makes it at line 902, so the old
    // src.indexOf("staleSentinelRefusal(") returned the COMMENT, and "before
    // the snapshot" stayed true with the real call moved anywhere below it.
    const raw = read("checks/mutations.ts");
    const call = preconditionCallIndex(raw);
    expect(call, "the harness must CALL the precondition, at module scope").toBeGreaterThan(-1);
    expect(raw, "and import it").toMatch(/from "\.\/tree_sentinel\.ts"/);

    const snapshot = codeIndexOf(raw, "ORIGINAL.set(");
    expect(snapshot, "the snapshot must exist for this to mean anything").toBeGreaterThan(-1);
    expect(call, "the refusal must come BEFORE the snapshot").toBeLessThan(snapshot);

    const firstRun = codeIndexOf(raw, "runSuite()");
    expect(firstRun).toBeGreaterThan(-1);
    expect(call, "and before the baseline run").toBeLessThan(firstRun);
  });

  it("POSITIVE CONTROL: the wiring assertion cannot be satisfied by a QUOTATION", () => {
    // Rule 24, the instrument checked before its output is believed. This is
    // the exact way the assertion first went wrong: checks/mutations.ts quotes
    // the wiring as data in its `find:` fields, so a file that only MENTIONS
    // the guard must not read as a file that runs it.
    const quotedOnly = [
      "const MUTATIONS = [",
      "  {",
      '    find: "const stale = staleSentinelRefusal(ROOT);",',
      '    replace: "if (stale !== null) { process.exit(1); }",',
      "  },",
      "];",
      "// const stale = staleSentinelRefusal(ROOT); in a comment does not count",
      "runTheGateWithoutChecking();",
    ].join("\n");
    expect(() => actsOnTheRefusal(quotedOnly, "quotation-only")).toThrow();

    // And the control's control: the same assertion passes on real wiring, so
    // the throw above is about the quoting and not about the helper refusing
    // everything.
    const realWiring = [
      'import { staleSentinelRefusal } from "./checks/tree_sentinel.ts";',
      "const stale = staleSentinelRefusal(ROOT);",
      "if (stale !== null) {",
      "  console.log(stale);",
      "  process.exit(1);",
      "}",
    ].join("\n");
    expect(() => actsOnTheRefusal(realWiring, "real-wiring")).not.toThrow();
  });

  it("POSITIVE CONTROL: a REGEX literal quoting the wiring does not count either", () => {
    // Measured, not imagined. codeOnly blanked comments and string literals and
    // knew nothing about regex literals, so a third way of writing the wiring
    // down without running it read straight through as code. A cold pass
    // replaced check.ts's six live lines with exactly these two regexes: the
    // full suite stayed at 276 green and the gate did not refuse a poisoned
    // tree, it ran five steps over it.
    //
    // This matters here specifically because checks/mutations.ts is a table of
    // source fragments held as data, and data is one edit away from being held
    // as a pattern instead of a string.
    const regexOnly = [
      'import { staleSentinelRefusal } from "./checks/tree_sentinel.ts";',
      "const WIRING = [",
      "  /const stale = staleSentinelRefusal(ROOT);/,",
      "  /if (stale !== null) { console.log(stale); process.exit(1); }/,",
      "];",
      "void WIRING;",
      "runTheGateWithoutChecking();",
    ].join("\n");
    expect(() => actsOnTheRefusal(regexOnly, "regex-only")).toThrow();
  });

  it("NEGATIVE CONTROL: a division is not swallowed as a regex", () => {
    // The other direction of the same fix, and it has to be pinned or the cure
    // is worse. check.ts really does divide: `((Date.now() - started) / 1000)`.
    // A lexer that calls every `/` a regex start blanks from there to the end of
    // the line, which would erase real wiring and turn this assertion into an
    // alarm that fires on correct code. Both operands are on one line here so
    // that a mis-lex would take the wiring with it.
    const withDivision = [
      "const seconds = elapsedMs / 1000; const stale = staleSentinelRefusal(ROOT);",
      "if (stale !== null) {",
      "  console.log(stale);",
      "  process.exit(1);",
      "}",
    ].join("\n");
    expect(() => actsOnTheRefusal(withDivision, "division")).not.toThrow();
  });

  it("POSITIVE CONTROL: wiring inside a function nothing calls does not count", () => {
    // The shape a cold pass found, and it is not the limit this file declared.
    // Every line of the guard is present, correct, in the right order and above
    // the first step. It is inside a function with no call site, so it never
    // runs. Measured: tsc, biome and all 276 tests stayed green and the gate did
    // not refuse.
    //
    // "Present in the file" and "runs when the file runs" are different claims,
    // and only the second one is a control.
    const insideAFunction = [
      'import { staleSentinelRefusal } from "./checks/tree_sentinel.ts";',
      "export function refuseIfTreeIsStale(): void {",
      "  const stale = staleSentinelRefusal(ROOT);",
      "  if (stale !== null) {",
      "    console.log(stale);",
      "    process.exit(1);",
      "  }",
      "}",
      "for (const step of STEPS) {",
      "  runStep(step);",
      "}",
    ].join("\n");
    expect(() => actsOnTheRefusal(insideAFunction, "inside-a-function")).toThrow();
  });

  it("POSITIVE CONTROL: the ordering is read from the CALL, not from prose quoting it", () => {
    // checks/mutations.ts mentions `staleSentinelRefusal(ROOT);` in a comment at
    // line 810 and calls it at line 902. An ordering assertion anchored on the
    // first occurrence anywhere in the file is therefore anchored on the
    // comment, and stays green with the real call moved anywhere below the
    // snapshot. Measured on the shipped file before this test existed.
    const commentFirst = [
      "// The precondition, `const stale = staleSentinelRefusal(ROOT);`, runs first.",
      "for (const f of TARGETS) ORIGINAL.set(f, readFileSync(f));",
      "const stale = staleSentinelRefusal(ROOT);",
      "if (stale !== null) {",
      "  process.exit(1);",
      "}",
    ].join("\n");
    const call = preconditionCallIndex(commentFirst);
    expect(call, "the real call must be located").toBeGreaterThan(-1);
    expect(call, "and it is AFTER the snapshot, which the prose hid").toBeGreaterThan(
      codeIndexOf(commentFirst, "ORIGINAL.set("),
    );
  });

  it("check.ts BINDS the refusal, TESTS it, and exits inside that block", () => {
    actsOnTheRefusal(read("check.ts"), "check.ts");
  });

  it("checks/mutations.ts BINDS the refusal, TESTS it, and exits inside that block", () => {
    // Stated separately from check.ts rather than swept over both, because a
    // rule enforced by one loop over two files is a rule nobody notices losing
    // a file. This repo has already paid for that once: the invisible-character
    // rule was absolute and its enforcement covered eight files.
    actsOnTheRefusal(read("checks/mutations.ts"), "checks/mutations.ts");
  });
});
