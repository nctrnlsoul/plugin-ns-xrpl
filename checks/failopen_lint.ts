// A narrow lint for the shapes that have actually caused a fail-open, here or
// in the vault's prior builds.
//
// Narrow is the point. A linter that shouts about everything gets muted, and a
// muted linter is worse than none because it looks like coverage. This reads
// only the files that decide whether something is reported or refused, and it
// knows a handful of patterns.
//
// Ported from HIGHWATER's checks/failopen_lint.py, which found a swallowed
// exception on its first run. This one found two real nullish fallbacks in
// src/core/address.ts and src/provider.ts within a minute of existing, and both
// were restructured rather than exempted.

import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const ROOT = join(import.meta.dirname, "..");

/** Only files that decide. Adding a file here is a deliberate act. */
const DECIDING_FILES = [
  "src/core/address.ts",
  "src/core/node-url.ts",
  "src/core/response.ts",
  "src/core/ratelimit.ts",
  "src/core/render.ts",
  "src/core/result.ts",
  "src/transport/client.ts",
  "src/provider.ts",
];

// Written as escapes, never as the characters themselves. Putting the literal
// characters in this file is the bug this rule exists to catch, and it happened:
// literal zero-width and bidi characters were written straight into a regex in
// src/core/render.ts and the file stopped parsing. In a string rather than a
// regex it would have parsed cleanly and shipped.
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]/;
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

interface Finding {
  file: string;
  line: number;
  rule: string;
  text: string;
}

const findings: Finding[] = [];

function report(file: string, line: number, rule: string, text: string) {
  findings.push({ file, line, rule, text: text.trim().slice(0, 110) });
}

/** True for a line that is entirely comment, so prose about a pattern is not the pattern. */
function isCommentLine(raw: string): boolean {
  const t = raw.trim();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");
}

/**
 * The two CHARACTER rules run over every .ts file under src/. The rest do not.
 *
 * That split is the whole design. CLAUDE.md bans literal invisible and control
 * characters in source without qualification, but this lint enforced it over
 * eight files, and the two that broke the rule were tests: they carried literal
 * NUL, BEL, ESC and U+202E RIGHT-TO-LEFT OVERRIDE. Measured cost, not a
 * theoretical one: grep classified both files as binary and silently skipped 44
 * of the suite's 173 `it(` sites, so a search over src/__tests__ returned a
 * clean-looking partial answer.
 *
 * Widening only these two keeps the promise at the top of this file. A linter
 * that shouts about everything gets muted, and a muted linter is worse than
 * none because it looks like coverage. A nullish fallback inside a test is
 * usually fine; a literal NUL inside a test is the same defect wherever it sits.
 */
function everyTsFileUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...everyTsFileUnder(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

/**
 * C1 controls, by code point rather than by a regex containing them.
 *
 * Not covered by CONTROL above, invisible in most editors, and written this way
 * so this file never has to hold the characters it bans.
 */
function hasC1Control(raw: string): boolean {
  for (const ch of raw) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && cp >= 0x80 && cp <= 0x9f) return true;
  }
  return false;
}

function checkCharacters(rel: string, source: string) {
  source.split("\n").forEach((raw, i) => {
    if (INVISIBLE.test(raw) || hasC1Control(raw)) {
      report(rel, i + 1, "literal-invisible-char", "line contains a literal invisible character");
    }
    if (CONTROL.test(raw)) {
      report(rel, i + 1, "literal-control-char", "line contains a literal control character");
    }
  });
}

for (const rel of DECIDING_FILES) {
  let source: string;
  try {
    source = readFileSync(join(ROOT, rel), "utf8");
  } catch {
    report(rel, 0, "missing-file", "a file this lint is supposed to read does not exist");
    continue;
  }

  // Invisible and control characters are checked on EVERY line, comments
  // included, because a comment is still a place they can hide.
  checkCharacters(rel, source);

  const lines = source.split("\n");

  lines.forEach((raw, i) => {
    const n = i + 1;

    if (isCommentLine(raw)) return;
    const code = raw.replace(/\/\/.*$/, "");

    // 1. A fallback on a path whose whole job is to refuse the unknown.
    //    A defaulted balance is the exact shape finding M-5 names.
    if (/\?\?\s*(0\b|""|''|\[\]|\{\}|false\b|true\b)/.test(code)) {
      report(rel, n, "nullish-fallback", raw);
    }
    if (/\|\|\s*(0\b|\[\]|\{\}|true\b)/.test(code)) {
      report(rel, n, "or-fallback", raw);
    }

    // 2. Loose equality lets "0" match 0 and null match undefined.
    if (/[^=!<>]==[^=]/.test(code) || /[^!]!=[^=]/.test(code)) {
      report(rel, n, "loose-equality", raw);
    }

    // 3. Substring host matching. endsWith("example.com") also accepts
    //    evil-example.com and example.com.attacker.test.
    if (/\b(hostname|host|url)\b[^;]*\.(endsWith|includes|startsWith|indexOf)\s*\(/i.test(code)) {
      report(rel, n, "substring-host-match", raw);
    }

    // 4. A catch that yields a success value turns a failure into an answer.
    if (/catch\s*(\([^)]*\))?\s*\{\s*return\s+(ok\(|true|\{\s*ok:\s*true)/.test(code)) {
      report(rel, n, "catch-returns-success", raw);
    }

    // 5. Reading a field off a possibly-hostile object through the prototype
    //    chain. In response.ts every read goes through own().
    if (rel.endsWith("response.ts") && /\b(result|accountData|line)\s*\[\s*["'`]/.test(code)) {
      report(rel, n, "non-own-property-read", raw);
    }
  });

  // 6. JSON.parse outside a try turns a malformed body into a thrown error,
  //    which this runtime converts into silence.
  const parseCount = (source.match(/JSON\.parse\(/g) ?? []).length;
  const guardedParse = (source.match(/try\s*\{[^}]*?JSON\.parse\(/gs) ?? []).length;
  if (parseCount > guardedParse) {
    report(
      rel,
      0,
      "unguarded-json-parse",
      `${parseCount} JSON.parse call(s), ${guardedParse} inside try`,
    );
  }
}

// Every OTHER .ts file under src/, character rules only. This is the half that
// was missing: the rule was absolute and the enforcement covered eight files.
const decidingSet = new Set(DECIDING_FILES.map((f) => join(ROOT, f)));
const otherSrcFiles = everyTsFileUnder(join(ROOT, "src")).filter((f) => !decidingSet.has(f));

for (const abs of otherSrcFiles) {
  checkCharacters(relative(ROOT, abs).split(sep).join("/"), readFileSync(abs, "utf8"));
}

// Rule 95: a sweep over an empty list passes vacuously. Say what was covered.
if (otherSrcFiles.length === 0) {
  report(
    "src",
    0,
    "empty-sweep",
    "the character sweep found no files to read, so it proved nothing",
  );
}

if (findings.length === 0) {
  console.log(
    `fail-open lint: clean across ${DECIDING_FILES.length} deciding files (all rules) ` +
      `and ${otherSrcFiles.length} further src files (character rules only)`,
  );
  process.exit(0);
}

console.log(`fail-open lint: ${findings.length} finding(s)\n`);
for (const f of findings) {
  console.log(`  ${f.file}:${f.line}  [${f.rule}]`);
  console.log(`      ${f.text}`);
}
console.log("\nEach of these is a shape that has produced a fail-open before.");
console.log("If one is genuinely correct here, restructure it rather than widening the rule.");
process.exit(1);
