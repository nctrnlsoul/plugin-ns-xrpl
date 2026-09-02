// D3. CLAUDE.md: never write literal invisible or control characters into
// source, use \u escapes.
//
// The rule was stated absolutely and enforced over eight files. The two it did
// not cover were test files, and they carried literal NUL, BEL, ESC, U+202E
// RIGHT-TO-LEFT OVERRIDE, U+200B, U+FEFF and U+2066. The cost was measured, not
// theoretical: grep classified both files as binary, so 44 of 173 `it(` sites,
// a quarter of the suite, were invisible to any text search over src/__tests__.
// A cold audit greppping the suite got a clean-looking partial answer.
//
// So the guard lives in the SUITE, not only in checks/failopen_lint.ts. The lint
// runs in the gate; the suite is what checks/mutations.ts can prove red.
//
// Nothing in this file may contain the characters it bans. Every one of them is
// built with String.fromCharCode.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(import.meta.dirname, "..");

/**
 * Invisible, zero-width and bidirectional ranges, as numbers.
 *
 * Written as code points rather than as a character class containing the
 * characters, because a detector that carries the defect it detects cannot be
 * trusted to report on it.
 */
const INVISIBLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x200b, 0x200f],
  [0x2028, 0x2029],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
];

/** True for a code point that must never appear literally in source. */
function isBannedLiteral(cp: number): boolean {
  // Tab, line feed and carriage return are how source is laid out.
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return false;
  if (cp < 0x20 || cp === 0x7f) return true;
  if (cp >= 0x80 && cp <= 0x9f) return true;
  return INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

function everyTsFileUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...everyTsFileUnder(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

interface Hit {
  file: string;
  line: number;
  codePoint: string;
}

function scan(source: string, label: string): Hit[] {
  const hits: Hit[] = [];
  source.split("\n").forEach((raw, i) => {
    for (const ch of raw) {
      const cp = ch.codePointAt(0);
      if (cp !== undefined && isBannedLiteral(cp)) {
        hits.push({
          file: label,
          line: i + 1,
          codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        });
      }
    }
  });
  return hits;
}

describe("no literal control or invisible characters anywhere in src/", () => {
  // The instrument is checked before its output is believed. If the scanner
  // cannot see a planted character, a clean sweep below means nothing.
  it("POSITIVE CONTROL: the scanner detects each banned character when planted", () => {
    for (const cp of [0x0000, 0x0007, 0x001b, 0x007f, 0x200b, 0x202e, 0x2066, 0xfeff]) {
      const planted = `const x = "a${String.fromCharCode(cp)}b";`;
      const hits = scan(planted, "synthetic");
      expect(hits, `U+${cp.toString(16)} must be detected`).toHaveLength(1);
      expect(hits[0]?.line).toBe(1);
    }
  });

  it("POSITIVE CONTROL: tab, newline and carriage return are NOT flagged", () => {
    expect(scan("a\tb\r\nc", "synthetic")).toHaveLength(0);
  });

  it("finds at least one .ts file to scan, so a clean sweep is not an empty one", () => {
    // Rule 95: prove the setup reached the state it claims. An empty file list
    // passes the sweep below vacuously.
    expect(everyTsFileUnder(SRC).length).toBeGreaterThan(15);
  });

  it("every .ts file under src/ is free of them", () => {
    const hits: Hit[] = [];
    for (const file of everyTsFileUnder(SRC)) {
      hits.push(...scan(readFileSync(file, "utf8"), file.slice(file.indexOf("src"))));
    }
    const rendered = hits.map((h) => `${h.file}:${h.line} ${h.codePoint}`).join("\n");
    expect(
      hits,
      `literal control or invisible characters in source. Use \\u escapes:\n${rendered}`,
    ).toHaveLength(0);
  });

  it("no source file is classified as binary by a null byte, so grep can read it", () => {
    // This is the property that actually bit: a NUL makes grep skip the file
    // silently, and a search over the suite then reports a clean partial answer.
    for (const file of everyTsFileUnder(SRC)) {
      expect(readFileSync(file, "utf8").includes(String.fromCharCode(0)), file).toBe(false);
    }
  });
});

// The SAME failure shape as the header above, one file over.
//
// That one was a rule stated absolutely and enforced over a hand-maintained list
// of eight files, and the two files the list did not name were the two that
// broke the rule. checks/failopen_lint.ts still keeps that hand-maintained list:
// DECIDING_FILES names every module whose fallbacks, coercions and loose
// equalities are checked, and everything not in it is checked for nothing but
// invisible characters.
//
// Found by a cold pass: src/core/turncache.ts was added to that array by hand,
// and deleting the one line leaves the gate GREEN, reporting "clean across 8
// deciding files". A list that can shrink without anything noticing is a list
// that will.
//
// Found by the NEXT cold pass, in the fix for that: this file checked only the
// src/core third of the rule the array's comment states, so removing
// src/transport/client.ts left the suite green at 369. The rule is now enforced
// whole, in both directions.
describe("the fail-open lint's own file list keeps up with the source", () => {
  const LINT = join(SRC, "..", "checks", "failopen_lint.ts");

  /** The array's contents, read from the array and not from the whole file. */
  function decidingFiles(): string[] {
    const source = readFileSync(LINT, "utf8");
    const start = source.indexOf("const DECIDING_FILES");
    const end = source.indexOf("];", start);
    expect(start, "the DECIDING_FILES array must be findable").toBeGreaterThan(-1);
    expect(end, "and it must be terminated").toBeGreaterThan(start);
    return [...source.slice(start, end).matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? "");
  }

  it("POSITIVE CONTROL: the list is read from the array, is not empty, and excludes prose", () => {
    // Reading the whole file instead would let a path mentioned in a COMMENT
    // satisfy every assertion below while the array no longer named it.
    const listed = decidingFiles();
    expect(listed.length).toBeGreaterThan(5);
    expect(listed).toContain("src/provider.ts");
    for (const entry of listed) expect(entry.endsWith(".ts"), entry).toBe(true);
  });

  /** The whole rule the array's own comment states, as a list of paths. */
  function requiredFiles(): string[] {
    const under = (dir: string) =>
      readdirSync(join(SRC, dir))
        .filter((name) => name.endsWith(".ts"))
        .map((name) => `src/${dir}/${name}`);
    return [...under("core"), ...under("transport"), "src/provider.ts"];
  }

  it("every module the rule names is a deciding file the lint actually reads", () => {
    // The rule stated in that array's comment is "every module under src/core,
    // plus the transport and the provider". This used to check only the src/core
    // third of it, so removing src/transport/client.ts left the suite green: a
    // comment describing a control the code did not implement, which is the
    // src/core/node-url.ts failure CLAUDE.md records by name.
    const listed = new Set(decidingFiles());
    const required = requiredFiles();

    // Rule 95: prove the setup reached the state it claims. An empty or
    // one-directory list passes the loop below having proved a third of it.
    expect(required.length, "the rule must cover files for this to check any").toBeGreaterThan(5);
    expect(required, "src/core is covered").toContain("src/core/turncache.ts");
    expect(required, "and so is the transport").toContain("src/transport/client.ts");
    expect(required, "and so is the provider").toContain("src/provider.ts");

    for (const file of required) {
      expect(
        listed.has(file),
        `${file} decides whether something is reported or refused, and the fail-open lint never reads it`,
      ).toBe(true);
    }
  });

  it("and names nothing the rule does not, so the list cannot drift the other way", () => {
    // The complement. Without it the array could accumulate paths that no longer
    // exist, and the lint reports "missing-file" for each one while the count in
    // its summary line keeps going up.
    const required = new Set(requiredFiles());
    for (const file of decidingFiles()) {
      expect(required.has(file), `${file} is listed but is not part of the stated rule`).toBe(true);
    }
  });
});
