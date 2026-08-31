// Mutation testing over bugs this repo has ACTUALLY had.
//
// Each entry reintroduces a real defect and demands the suite turn red. A
// survivor means the guard for that bug is decorative.
//
// This is Build Failure Lessons 91b as code: for any test named after a specific
// failure, delete the thing being tested and confirm the test goes red. That is
// a discipline, and disciplines get skipped.
//
// Two entries are not hypotheticals and not borrowed. They are bugs that existed
// in this file's own repo during the session that wrote it:
//
//   exponent-branch-removed  the decimal pattern had no exponent branch, so real
//                            ledger balances like -4263500000000000e-27 were
//                            rejected and one bad line refused an entire account.
//                            Found by running the real path, not by any test.
//   no-total-budget          each request had its own timeout but the lookup had
//                            no overall budget, so a worst case of four requests
//                            at 8,000ms each ran past the runtime's silent
//                            30,000ms cutoff, where the spoken refusal is
//                            discarded and the whole design fails.
//
// The rest are the failure classes _system/CHANGE_GATE names, instantiated
// against this code: coercion to zero, a removed cap, a guard crash becoming
// permission, a trusted attacker-written field, a substring allowlist.
//
// SETUP IS PROVEN, NOT ASSUMED. If a mutation's search text is not found, the
// mutation silently does nothing and the suite stays green, which would read as
// "the guard held" when nothing was tested. That is Build Failure Lessons rule
// 95: a test is usually disabled by its setup, not its assertion. A stale entry
// is a hard failure here, not a skip.

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");

interface Mutation {
  id: string;
  file: string;
  find: string;
  replace: string;
  why: string;
}

const MUTATIONS: Mutation[] = [
  {
    id: "exponent-branch-removed",
    file: "src/core/response.ts",
    find: "const DECIMAL_PATTERN = /^-?[0-9]+(\\.[0-9]+)?([eE][-+]?[0-9]+)?$/;",
    replace: "const DECIMAL_PATTERN = /^-?[0-9]+(\\.[0-9]+)?$/;",
    why: "real ledger balances use exponent form; without the branch legitimate lines are dropped",
  },
  {
    id: "no-total-budget",
    file: "src/core/bounds.ts",
    find: "TOTAL_LOOKUP_BUDGET_MS: 20_000,",
    replace: "TOTAL_LOOKUP_BUDGET_MS: 60_000,",
    why: "a budget above the runtime's 30s cutoff means the refusal is discarded before it is read",
  },
  {
    id: "balance-defaults-to-zero",
    file: "src/core/response.ts",
    find: "  if (!isDropsBalance(balance)) {",
    replace: "  if (false) {",
    why: "finding M-5: a missing balance defaulted rather than refused reports 0 XRP with confidence",
  },
  {
    id: "unvalidated-ledger-accepted",
    file: "src/core/response.ts",
    find: '  if (own(result, "validated") !== true) {',
    replace: '  if (own(result, "validated") === false) {',
    why: "a missing validated flag would be assumed true, reporting an unconfirmed ledger as fact",
  },
  {
    id: "error-body-ignored",
    file: "src/core/response.ts",
    find: '  if (typeof error === "string" && error !== "") {',
    replace: '  if (false && typeof error === "string" && error !== "") {',
    why: "rippled reports errors at HTTP 200 in the body; ignoring them treats an error as data",
  },
  {
    id: "allowlist-becomes-substring",
    file: "src/core/node-url.ts",
    find: "  if (!ALLOWED_NODE_HOSTS.includes(host)) {",
    replace: "  if (!ALLOWED_NODE_HOSTS.some((h) => host.endsWith(h))) {",
    why: "endsWith also accepts evil-xrplcluster.com and is the classic allowlist bug",
  },
  {
    id: "credentials-allowed-in-url",
    file: "src/core/node-url.ts",
    find: '  if (url.username !== "" || url.password !== "") {',
    replace: '  if (false && (url.username !== "" || url.password !== "")) {',
    why: "https://allowed.host@attacker.test/ resolves to attacker.test",
  },
  {
    id: "checksum-skipped",
    file: "src/core/address.ts",
    find: "  if (!checksumMatches(expected, actual)) {",
    replace: "  if (false && !checksumMatches(expected, actual)) {",
    why: "without the checksum any well-shaped string is accepted and sent to the network",
  },
  {
    id: "currency-hex-decoded",
    file: "src/core/render.ts",
    find: "  if (HEX_CURRENCY.test(code)) return `hex:${code.toUpperCase().slice(0, 32)}`;",
    replace:
      '  if (HEX_CURRENCY.test(code)) return Buffer.from(code, "hex").toString("ascii").replace(/\\0+$/, "");',
    why: "finding H-1: a 40-hex currency code carries 20 attacker-chosen bytes into the prompt",
  },
  {
    id: "render-cap-removed",
    file: "src/core/render.ts",
    find: "  if (report.length <= BOUNDS.MAX_RENDERED_CHARS) return report;",
    replace: "  if (true) return report;",
    why: "finding H-2: without a total cap the whole report lands in the context unbounded",
  },
  {
    id: "truncation-goes-silent",
    file: "src/core/render.ts",
    find: "  if (notShown > 0 || notRetrieved > 0) {",
    replace: "  if (false && (notShown > 0 || notRetrieved > 0)) {",
    why: "a silently shortened list reads to the model as a complete one",
  },
  {
    id: "ratelimit-allows-on-malformed-state",
    file: "src/core/ratelimit.ts",
    find: "  if (!Array.isArray(stamps)) {",
    replace: "  if (false) {",
    why: "a limiter that allows when its own state is corrupt is one an attacker switches off",
  },
  {
    id: "ratelimit-cap-off-by-one",
    file: "src/core/ratelimit.ts",
    find: "  if (live.length >= BOUNDS.RATE_LIMIT_MAX_REQUESTS) {",
    replace: "  if (live.length > BOUNDS.RATE_LIMIT_MAX_REQUESTS) {",
    why: "a removed or loosened cap is one of the seeded failure classes",
  },
  {
    id: "prototype-read-allowed",
    file: "src/core/response.ts",
    find: "  return Object.hasOwn(obj, key) ? obj[key] : undefined;",
    replace: "  return obj[key];",
    why: "reading through the prototype chain lets a polluted prototype supply absent data",
  },
  {
    id: "provider-throws-instead-of-speaking",
    file: "src/provider.ts",
    find: "      } catch (error) {",
    replace: "      } catch (error) { if (error) throw error;",
    why: "the measured core finding: a thrown refusal is erased by the runtime and becomes silence",
  },

  // ---------------------------------------------------------------------------
  // Everything below is a mutation an ADVERSARIAL RED-PROOF confirmed the suite
  // could not see. Eleven guards were handed to agents that had not written
  // them, briefed only with the requirement and the words "make this go red".
  // They returned 46 independently reproduced holes.
  //
  // Every entry here SURVIVED at that point. They are in the harness so the
  // tests written in response are proved to catch them, rather than asserted to.
  //
  // The pattern behind almost all of them: a guard was pinned by ONE example,
  // so any weakening that still rejected that single example stayed green.
  // ---------------------------------------------------------------------------

  {
    id: "rp-credentials-one-sided",
    file: "src/core/node-url.ts",
    find: '  if (url.username !== "" || url.password !== "") {',
    replace: '  if (url.username !== "" && url.password !== "") {',
    why: "the only credential test set BOTH halves, so a URL carrying one half went out with the secret on the wire",
  },
  {
    id: "rp-allowlist-subdomain-wildcard",
    file: "src/core/node-url.ts",
    find: "  if (!ALLOWED_NODE_HOSTS.includes(host)) {",
    replace: "  if (!ALLOWED_NODE_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) {",
    why: "a subdomain the operator does not control is a different trust boundary from the apex",
  },
  {
    id: "rp-allowlist-reversed-comparison",
    file: "src/core/node-url.ts",
    find: "  if (!ALLOWED_NODE_HOSTS.includes(host)) {",
    replace: "  if (!ALLOWED_NODE_HOSTS.some((h) => h.endsWith(host))) {",
    why: "every negative host in the original suite was LONGER than an allowlist entry, so reversing the operands was invisible",
  },
  {
    id: "rp-url-passed-through-not-rebuilt",
    file: "src/core/node-url.ts",
    find: "  return ok(`https://${host}${port}${url.pathname}${url.search}`);",
    replace: "  return ok(url.toString());",
    why: "nothing asserted the URL handed to fetch, so the returned value could carry userinfo the checks had rejected",
  },
  {
    id: "rp-private-range-check-removed",
    file: "src/core/node-url.ts",
    find: "  if (IPV4.test(h)) return true;",
    replace: "  if (false && IPV4.test(h)) return true;",
    why: "the file once CLAIMED to block private ranges while no such code existed; this proves the blanket IP refusal that replaced the claim is real",
  },
  {
    id: "rp-validated-assumed-when-absent",
    file: "src/core/response.ts",
    find: '  if (own(result, "validated") !== true) {',
    replace: '  if (Object.hasOwn(result, "validated") && result.validated !== true) {',
    why: "setting the key to undefined creates an own property, so absence was never actually tested",
  },
  {
    id: "rp-validated-truthiness",
    file: "src/core/response.ts",
    find: '  if (own(result, "validated") !== true) {',
    replace: '  if (!own(result, "validated")) {',
    why: "the suite only supplied false and undefined, both falsy, so a truthiness check accepted any junk as confirmation",
  },
  {
    id: "rp-status-catchall-gated-off",
    file: "src/core/response.ts",
    find: '  if (status !== "success") {',
    replace: '  if (status !== "success" && error !== undefined) {',
    why: "every error fixture also carried a string error, so the status catch-all could be made dead code unnoticed",
  },
  {
    id: "rp-notfound-message-reads-as-zero",
    file: "src/core/response.ts",
    find: '        "That XRPL account does not exist on the validated ledger. The ledger has no record of it, which is different from an account that exists and holds nothing.",',
    replace: '        "That XRPL account holds 0.000000 XRP.",',
    why: "nothing pinned the CONTENT of the message, so the exact failure this module exists to prevent could be reintroduced as text",
  },
  {
    id: "rp-balance-length-unbounded",
    file: "src/core/response.ts",
    find: "v.length <= MAX_DROPS_DIGITS && ",
    replace: "",
    why: "a 50,000-digit balance passed validation and then crowded every other field out of the size-capped report",
  },
  {
    id: "rp-balance-lowercase-decoy",
    file: "src/core/response.ts",
    find: '  const balance = own(accountData, "Balance");',
    replace: '  const balance = own(accountData, "Balance") ?? own(accountData, "balance");',
    why: "a response with no Balance key but a lowercase decoy was reported as a real balance",
  },
  {
    id: "rp-truncation-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (notShown > 0 || notRetrieved > 0) {",
    replace: "  if (notShown > 1 || notRetrieved > 1) {",
    why: "the notice was pinned with 500 lines and 4,000 not retrieved, so omitting exactly one went unreported",
  },
  {
    id: "rp-unreadable-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (unreadable > 0) {",
    replace: "  if (unreadable > 1) {",
    why: "the notice was pinned with 3 dropped lines, so dropping exactly one went unreported",
  },
  {
    id: "rp-more-available-suppressed-when-empty",
    file: "src/core/render.ts",
    find: "  if (input?.moreAvailable === true) {",
    replace: "  if (input?.moreAvailable === true && all.length > 0) {",
    why: "both moreAvailable tests passed a non-empty list, so suppressing the notice on an empty page was invisible",
  },
  {
    id: "rp-size-cap-marker-dropped",
    file: "src/core/render.ts",
    find: "  return report.slice(0, BOUNDS.MAX_RENDERED_CHARS - marker.length) + marker;",
    replace: "  return report.slice(0, BOUNDS.MAX_RENDERED_CHARS);",
    why: "the only cap test asserted length alone, so silently cutting the report satisfied it exactly",
  },
  {
    id: "rp-currency-guard-bypassed-at-call-site",
    file: "src/core/render.ts",
    find: "currency=${renderCurrencyCode(line?.currency)}",
    replace: "currency=${sanitizeLedgerText(line?.currency)}",
    why: "the guard kept passing its own unit tests as dead code while the report rendered the ledger's currency verbatim",
  },
  {
    id: "rp-hex-currency-unanchored",
    file: "src/core/render.ts",
    find: "const HEX_CURRENCY = /^[0-9A-Fa-f]{40}$/;",
    replace: "const HEX_CURRENCY = /[0-9A-Fa-f]{40}/;",
    why: "unanchored, any string CONTAINING a hex run was echoed back verbatim under a label asserting it was safe",
  },
  {
    id: "rp-ratelimit-accepts-non-finite",
    file: "src/core/ratelimit.ts",
    find: '    if (typeof s !== "number" || !Number.isFinite(s)) {',
    replace: '    if (typeof s !== "number") {',
    why: "NaN and Infinity are typeof number, pass validation, then evaporate in the filter, so the count reads zero",
  },
  {
    id: "rp-ratelimit-off-when-anything-expired",
    file: "src/core/ratelimit.ts",
    find: "  if (live.length >= BOUNDS.RATE_LIMIT_MAX_REQUESTS) {",
    replace:
      "  if (live.length === stamps.length && live.length >= BOUNDS.RATE_LIMIT_MAX_REQUESTS) {",
    why: "one stale timestamp anywhere switched the limiter off entirely, and real histories always contain stale entries",
  },
  {
    id: "rp-ratelimit-scans-only-a-prefix",
    file: "src/core/ratelimit.ts",
    find: "  for (const s of stamps) {",
    replace: "  for (const s of stamps.slice(0, 4)) {",
    why: "a corrupt entry at index 4 or later was never detected, so the limiter returned ok on corrupt state",
  },
  {
    id: "rp-prune-keeps-oldest",
    file: "src/core/ratelimit.ts",
    find: "  return live.slice(-BOUNDS.RATE_LIMIT_MAX_REQUESTS * 2);",
    replace: "  return live.slice(0, BOUNDS.RATE_LIMIT_MAX_REQUESTS * 2);",
    why: "keeping the oldest entries discards exactly the recent ones that will still be inside the window next check",
  },
  {
    id: "rp-lines-refusal-silenced",
    file: "src/provider.ts",
    find: '    if ("ok" in linesResult && linesResult.ok === false) return speak(linesResult);',
    replace: '    if ("ok" in linesResult && linesResult.ok === false) return SILENT;',
    why: "THE headline hole: the whole second half of the lookup could fail and the provider contributed nothing",
  },
  {
    id: "rp-address-pattern-narrowed",
    file: "src/core/address.ts",
    find: "export const ADDRESS_CANDIDATE_PATTERN = /r[1-9A-HJ-NP-Za-km-z]{24,34}/g;",
    replace: "export const ADDRESS_CANDIDATE_PATTERN = /r[1-9A-HJ-NP-Za-km-z]{32,34}/g;",
    why: "short but valid classic addresses stopped being detected, so a real account produced silence",
  },
];

function runSuite(): { red: boolean; summary: string } {
  const r = spawnSync(join(ROOT, "node_modules", ".bin", "vitest"), ["run", "src/__tests__"], {
    cwd: ROOT,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const line = out.split("\n").find((l) => l.includes("Tests ")) ?? "(no summary line)";
  return { red: r.status !== 0, summary: line.trim() };
}

// Snapshot every file this harness can touch, before it touches anything.
const TARGETS = [...new Set(MUTATIONS.map((m) => m.file))];
const ORIGINAL = new Map<string, string>();
for (const f of TARGETS) ORIGINAL.set(f, readFileSync(join(ROOT, f), "utf8"));

function restoreAll() {
  for (const [f, content] of ORIGINAL) writeFileSync(join(ROOT, f), content, "utf8");
}

const survivors: Mutation[] = [];
const stale: Mutation[] = [];
let baseline = "";

try {
  const base = runSuite();
  baseline = base.summary;
  if (base.red) {
    console.log("mutations: the suite is RED before any mutation. Fix that first.");
    console.log(`  ${base.summary}`);
    process.exit(1);
  }
  console.log(`mutations: baseline green (${baseline})`);
  console.log(`mutations: applying ${MUTATIONS.length} historical defects\n`);

  for (const m of MUTATIONS) {
    const original = ORIGINAL.get(m.file);
    if (original === undefined) {
      stale.push(m);
      continue;
    }

    // Rule 95: prove the setup reached the state it claims.
    const occurrences = original.split(m.find).length - 1;
    if (occurrences !== 1) {
      console.log(`  [${m.id}] STALE: search text found ${occurrences} times, expected exactly 1`);
      stale.push(m);
      continue;
    }

    writeFileSync(join(ROOT, m.file), original.replace(m.find, m.replace), "utf8");
    const result = runSuite();
    writeFileSync(join(ROOT, m.file), original, "utf8");

    if (result.red) {
      console.log(`  [${m.id}] caught`);
    } else {
      console.log(`  [${m.id}] SURVIVED  <-- the guard for this is decorative`);
      console.log(`      ${m.why}`);
      console.log(`      ${result.summary}`);
      survivors.push(m);
    }
  }
} finally {
  restoreAll();
}

// The tree must come back byte-identical. A harness that leaves a mutation
// behind is worse than no harness.
let dirty = 0;
for (const [f, content] of ORIGINAL) {
  if (readFileSync(join(ROOT, f), "utf8") !== content) {
    console.log(`\nRESTORE FAILED: ${f} is not byte-identical to its original`);
    dirty++;
  }
}

console.log();
if (dirty > 0) {
  console.log(`mutations: RESTORE FAILED on ${dirty} file(s). Check your working tree NOW.`);
  process.exit(1);
}
console.log("mutations: all files restored byte-identical");

if (stale.length > 0) {
  console.log(`\nmutations: ${stale.length} STALE entr(ies). Each one tested NOTHING:`);
  for (const m of stale) console.log(`  - ${m.id} (${m.file})`);
  console.log("A stale mutation is a silent hole in this harness. Update its search text.");
  process.exit(1);
}

if (survivors.length > 0) {
  console.log(`\nmutations: ${survivors.length} SURVIVOR(S). The suite did not notice:`);
  for (const m of survivors) console.log(`  - ${m.id}: ${m.why}`);
  process.exit(1);
}

console.log(`mutations: ${MUTATIONS.length} defects reintroduced, ${MUTATIONS.length} caught`);
process.exit(0);
