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
