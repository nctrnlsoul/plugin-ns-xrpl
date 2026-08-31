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

import { readFileSync } from "node:fs";
import { join } from "node:path";

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

for (const rel of DECIDING_FILES) {
  let source: string;
  try {
    source = readFileSync(join(ROOT, rel), "utf8");
  } catch {
    report(rel, 0, "missing-file", "a file this lint is supposed to read does not exist");
    continue;
  }

  const lines = source.split("\n");

  lines.forEach((raw, i) => {
    const n = i + 1;

    // Invisible and control characters are checked on EVERY line, comments
    // included, because a comment is still a place they can hide.
    if (INVISIBLE.test(raw)) {
      report(rel, n, "literal-invisible-char", "line contains a literal invisible character");
    }
    if (CONTROL.test(raw)) {
      report(rel, n, "literal-control-char", "line contains a literal control character");
    }

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

if (findings.length === 0) {
  console.log(`fail-open lint: clean across ${DECIDING_FILES.length} deciding files`);
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
