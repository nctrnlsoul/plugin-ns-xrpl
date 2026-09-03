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
import {
  buildSentinel,
  clearSentinel,
  mayClearSentinel,
  sentinelPath,
  sha256Of,
  staleSentinelRefusal,
  writeSentinel,
} from "./tree_sentinel.ts";

const ROOT = join(import.meta.dirname, "..");

interface Mutation {
  id: string;
  file: string;
  find: string;
  replace: string;
  why: string;
  /**
   * Decode \uXXXX in `replace` before writing it.
   *
   * Needed for exactly one class this file otherwise cannot express: a LITERAL
   * control or invisible character in source. Writing one here would put the
   * defect inside the harness that tests for it, and CLAUDE.md bans it outright.
   * So the escape is stored and decoded at apply time.
   */
  decodeEscapes?: boolean;
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
    // Search text updated when D2 rewrote this line to stop cutting the code to
    // 32 digits. The harness caught the drift itself: a stale entry is a hard
    // failure here, not a skip, because a search text that matches nothing
    // mutates nothing and reads as "the guard held".
    find: "  if (HEX_CURRENCY.test(code)) return `${HEX_LABEL}${code.toUpperCase()}`;",
    replace:
      '  if (HEX_CURRENCY.test(code)) return Buffer.from(code, "hex").toString("ascii").replace(/\\0+$/, "");',
    why: "finding H-1: a 40-hex currency code carries 20 attacker-chosen bytes into the prompt",
  },
  {
    id: "render-cap-removed",
    file: "src/core/render.ts",
    // Search text updated when F6 gave the size search a SECOND stage, which
    // gives up other-address names after it has given up trust rows. The old
    // one-line anchor then matched both loops and the harness called it STALE,
    // which is the fifth time that mechanism has caught its own drift.
    find:
      "    const report = build(kept, BOUNDS.MAX_ECHOED_ADDRESSES);\n" +
      "    if (report.length <= BOUNDS.MAX_RENDERED_CHARS) return report;",
    replace:
      "    const report = build(kept, BOUNDS.MAX_ECHOED_ADDRESSES);\n    if (true) return report;",
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
    // Search text updated when F1 restructured the renderer. The harness caught
    // the drift itself and went RED rather than quietly testing nothing, which
    // is the whole reason a stale entry is a hard failure here.
    //
    // The path this guards also moved. It is now the LAST RESORT only: reached
    // when the header alone overruns the cap, so there are no rows left to drop.
    // A hard cut still has to be spoken, and src/__tests__/render-redproof.ts
    // pins the marker on exactly that path.
    // Search text updated again when F6 gave build() a second parameter. The
    // hard cut runs over build(0, 0), zero names, so a character cut can never
    // end mid-address.
    find: "  return build(0, 0).slice(0, BOUNDS.MAX_RENDERED_CHARS - marker.length) + marker;",
    replace: "  return build(0, 0).slice(0, BOUNDS.MAX_RENDERED_CHARS);",
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
    // Search text updated twice, and both times the harness caught the drift
    // itself rather than quietly testing nothing: first when D6 gave speak() its
    // second argument, then when the in-turn cache put this branch through
    // remember(), and again when remember() moved into run() and stopped
    // taking the key and the clock as arguments.
    // The REPLACE has to move with the FIND, and once it did not. `SILENT`
    // stopped existing when the shared singleton became a silent() factory, so
    // this entry no longer silenced the branch: it produced code that does not
    // compile, the provider threw a ReferenceError, the outer catch spoke
    // INTERNAL_ERROR, and the harness recorded a "catch" earned by an unrelated
    // typecheck test. MEASURED: the only failing test was
    // package-surface.test.ts's tsbuildinfo one, and the provider still SPOKE.
    //
    // A mutation whose replace does not compile tests the compiler. Staleness is
    // a hard failure here for the find and is invisible for the replace, so the
    // replace is the half that has to be re-read by hand.
    //
    // Search text updated a fourth time when F8 gave speak() its unreadable-run
    // count. The harness caught the drift itself, as it has every time.
    find: '    if ("ok" in linesResult && linesResult.ok === false) {\n      return remember(speak(linesResult, allNamed, hidden, cacheState));\n    }',
    replace: '    if ("ok" in linesResult && linesResult.ok === false) return silent();',
    why: "THE headline hole: the whole second half of the lookup could fail and the provider contributed nothing",
  },
  {
    id: "rp-address-pattern-narrowed",
    file: "src/core/address.ts",
    find: "export const ADDRESS_CANDIDATE_PATTERN = /r[1-9A-HJ-NP-Za-km-z]{24,34}/g;",
    replace: "export const ADDRESS_CANDIDATE_PATTERN = /r[1-9A-HJ-NP-Za-km-z]{32,34}/g;",
    why: "short but valid classic addresses stopped being detected, so a real account produced silence",
  },

  // ---------------------------------------------------------------------------
  // Everything below reintroduces a defect a COLD VERIFICATION pass found in the
  // shipped artifact, having read the claims and not the build. Four defects,
  // D1 to D4. Each was measured before it was fixed, and each entry here is the
  // measurement turned into something that has to stay caught.
  // ---------------------------------------------------------------------------

  // D1. The tarball shipped dist/tsconfig.tsbuildinfo, 163.4 kB, 57% of the
  // unpacked package, and the guard against it could not fail.
  {
    id: "d1-buildinfo-back-in-dist",
    file: "tsconfig.json",
    find: '"tsBuildInfoFile": "./.tsbuildinfo",',
    replace: '"tsBuildInfoFile": "./dist/tsconfig.tsbuildinfo",',
    why: "tsc --noEmit writes the build info into outDir, so every typecheck re-contaminated the tarball",
  },
  {
    id: "d1-prepublish-hook-removed",
    file: "package.json",
    find: '"prepublishOnly": "bun run verify"',
    replace: '"prepublishOnlyDisabled": "bun run verify"',
    why: "npm rebuilds nothing on its own, so without this hook publish ships whatever is in dist",
  },
  {
    id: "d1-package-check-rebuilds-before-looking",
    file: "checks/package_entries.ts",
    find: 'if (existsSync(join(ROOT, "dist"))) {',
    replace: "if (false) {",
    why: "THE DEEPER DEFECT: the guard built first, and build.ts deletes dist, so it cleaned its own subject before measuring and printed no-build-metadata against a contaminated tree",
  },
  {
    id: "d1-tsbuildinfo-term-dropped",
    file: "checks/pack_listing.ts",
    find: 'export const BANNED_BUILD_METADATA: readonly string[] = ["tsbuildinfo", ".env", "node_modules"];',
    replace: 'export const BANNED_BUILD_METADATA: readonly string[] = [".env", "node_modules"];',
    why: "the one term that actually shipped, removed from the list the scanner reads",
  },

  // D2. A 40-hex currency code was cut to 32 with no notice, so two codes
  // differing only in their last four bytes rendered identically.
  {
    id: "d2-currency-recut-to-32",
    file: "src/core/render.ts",
    find: "  if (HEX_CURRENCY.test(code)) return `${HEX_LABEL}${code.toUpperCase()}`;",
    replace:
      "  if (HEX_CURRENCY.test(code)) return `${HEX_LABEL}${code.toUpperCase().slice(0, 32)}`;",
    why: "the original defect: distinct tokens collide in a report whose only job is to be accurate",
  },
  {
    id: "d2-truncation-notice-dropped",
    file: "src/core/render.ts",
    find: "  const label = `hex-truncated-from-${code.length}-chars:`;",
    replace: "  const label = HEX_LABEL;",
    why: "a shortened value wearing the complete-value label is silent truncation, which invariant 10 forbids",
  },

  // D3. Literal control and bidi characters in two test files made grep treat
  // both as binary, hiding 44 of 173 test sites from any text search.
  {
    id: "d3-literal-invisible-in-source",
    file: "src/core/render.ts",
    find: "const DROPS_PER_XRP = 1_000_000n;",
    replace: "const DROPS_PER_XRP = 1_000_000n; // \\u200B",
    decodeEscapes: true,
    why: "a literal zero-width space in source, the exact class that hid a quarter of the suite from grep",
  },
  {
    id: "d3-hygiene-scanner-blind-to-bidi",
    file: "src/__tests__/source-hygiene.test.ts",
    find: "  [0x202a, 0x202e],",
    replace: "  [0x202a, 0x202d],",
    why: "narrowing the range past U+202E RIGHT-TO-LEFT OVERRIDE leaves the sweep running and blind, which the positive control exists to catch",
  },

  // D4. The trust lines' own ledger index was computed and discarded, so the
  // report attributed them to the balance's ledger.
  {
    id: "d4-lines-ledger-index-discarded",
    file: "src/provider.ts",
    find: "        linesLedgerIndex: ledgerIndex,",
    replace: "        linesLedgerIndex: undefined,",
    why: "the original defect: the provider held both indices and threw one away",
  },
  {
    id: "d4-lines-ledger-borrowed-from-balance",
    file: "src/core/render.ts",
    find: "  out.push(`  trust_lines_ledger_index: ${renderCount(linesLedger)}`);",
    replace:
      "  out.push(`  trust_lines_ledger_index: ${renderCount(linesLedger ?? balanceLedger)}`);",
    why: "never default an absent value: borrowing the balance's ledger states as fact the one thing not known",
  },
  {
    id: "d4-mismatch-notice-removed",
    file: "src/core/render.ts",
    find: "    linesLedger !== balanceLedger",
    replace: "    false && linesLedger !== balanceLedger",
    why: "two ledgers combined into one report with nothing saying so",
  },
  {
    id: "d4-spread-notice-removed",
    file: "src/core/render.ts",
    find: "  if (input?.linesLedgerVaried === true) {",
    replace: "  if (false) {",
    why: "a paginated list straddling two ledgers may double-count or omit entries, and said nothing",
  },

  // ---------------------------------------------------------------------------
  // A SECOND cold verification pass, run against the tree the four repairs above
  // produced. It DISPROVED the standing claim that every truncation, omission
  // and drop is stated with a count.
  //
  // F1 was a live defect in the renderer. F2 was a defect in the tests: the
  // shipped behaviour was right and nothing pinned it. F5 was a defect in the
  // published dependency surface. Every entry below is that pass's measurement
  // turned into something that has to stay caught.
  // ---------------------------------------------------------------------------

  // F1. The size cap sliced the joined report, so rows vanished with no count
  // while trust_lines_shown still claimed the pre-cap number. Measured through
  // the real provider with ordinary mainnet values: 23 trust lines carrying
  // 40-hex currency codes made the report say 23 and print 22.
  {
    id: "f1-size-cap-count-removed",
    file: "src/core/render.ts",
    find: "    if (sizeCapped > 0) {",
    replace: "    if (false) {",
    why: "the size cap dropped whole rows and said nothing, which is the one thing invariant 10 forbids",
  },
  {
    id: "f1-shown-count-not-corrected",
    file: "src/core/render.ts",
    find: "    out.push(`  trust_lines_shown: ${kept}`);",
    replace: "    out.push(`  trust_lines_shown: ${rows.length}`);",
    why: "the original defect: the claimed count came from the pre-cap list, so the report stated 25 and printed 12",
  },
  {
    id: "f1-row-cut-in-half",
    file: "src/core/render.ts",
    find: "  for (let kept = rows.length; kept >= 0; kept--) {",
    replace: "  for (let kept = rows.length; kept >= rows.length; kept--) {",
    why: "without the search the report falls to the hard slice, which ends the last row mid-value and still reads as a row",
  },

  // F2. The count in each notice was asserted only against the WHOLE report, so
  // an unrelated digit in the fixture satisfied it. Replacing a count with a
  // word left all 215 tests green.
  {
    id: "f2-unreadable-count-dropped",
    file: "src/core/render.ts",
    find: "`  trust_lines_unreadable: ${unreadable} returned by the ledger but not readable, so they were omitted from this report.`",
    replace:
      "`  trust_lines_unreadable: some returned by the ledger but not readable, so they were omitted from this report.`",
    why: 'THE F2 SURVIVOR: the only count assertion was toContain("3") against a report whose balance 56774133566 already held a 3',
  },
  {
    id: "f2-truncation-counts-dropped",
    file: "src/core/render.ts",
    find: "`  trust_lines_truncated: ${notShown} returned but not shown, ${notRetrieved} not retrieved. This report is INCOMPLETE and must not be described as a full list.`",
    replace:
      "`  trust_lines_truncated: some returned but not shown, some not retrieved. This report is INCOMPLETE and must not be described as a full list.`",
    why: 'pinned by /500/ and toContain("4000") against the whole report, both of which other lines already satisfied',
  },
  {
    id: "f2-mismatch-line-drops-its-numbers",
    file: "src/core/render.ts",
    find: "`  trust_lines_ledger_mismatch: the balance is from ledger ${balanceLedger} and the trust lines are from ledger ${linesLedger}. This report combines two ledgers and is not a single point-in-time view of the account.`",
    replace:
      "`  trust_lines_ledger_mismatch: the balance and the trust lines are from different ledgers. This report combines two ledgers and is not a single point-in-time view of the account.`",
    why: "both numbers were asserted against the whole report, where the ledger_index and trust_lines_ledger_index lines already carried them",
  },
  {
    id: "f2-currency-truncation-label-drops-its-length",
    file: "src/core/render.ts",
    find: "  const label = `hex-truncated-from-${code.length}-chars:`;",
    replace: "  const label = `hex-truncated-from-many-chars:`;",
    why: 'the original length was pinned by toContain("60"), which the hex payload itself can satisfy (a backtick encodes to 60)',
  },
  {
    id: "f2-notfound-message-generic",
    file: "src/core/response.ts",
    find: '        "That XRPL account does not exist on the validated ledger. The ledger has no record of it, which is different from an account that exists and holds nothing.",',
    replace: '        "The XRPL node could not answer that lookup.",',
    why: 'still contains the substring "not", so the old toContain("not") assertions could not tell a not-found report from any other refusal',
  },
  {
    id: "f2-refusal-prefix-changed",
    file: "src/core/render.ts",
    // Search text updated four times: when D6 appended the other-addresses
    // notice here, when F6 made that notice a list of lines behind `tail`, when
    // F7 lifted the prefix into `head` so the notice could be given the room
    // actually left after it, and when F9 MOVED the whole refusal renderer out
    // of src/provider.ts. It moved because the head was the one piece of report
    // content with no bound and no sanitiser, and a decision made inside the
    // provider is a decision the suite can only reach through the provider.
    find: 'const REFUSAL_PREFIX = "XRPL lookup refused. ";',
    replace: 'const REFUSAL_PREFIX = "Lookup refused. ";',
    why: 'runtime-integration asserted toContain("XRPL") on the prompt, and the test character is named "XRPL Test Agent", so it passed on the name',
  },

  // F5. Declared under dependencies at an exact prerelease pin, and never loaded
  // at runtime: every import is `import type` and the bundle imports only
  // node:crypto. A plugin does not depend on its host.
  {
    id: "f5-elizaos-back-to-hard-dependency",
    file: "package.json",
    find: '  "peerDependencies": {\n    "@elizaos/core": ">=2.0.3-beta.7 <3.0.0-0"\n  },',
    replace: '  "dependencies": {\n    "@elizaos/core": "2.0.3-beta.7"\n  },',
    why: "forces a beta this package never loads into every consumer's tree, and pins them to one build of the host that is loading it",
  },

  // ---------------------------------------------------------------------------
  // D6. The one place X-006 recorded this package breaking its own rule, left
  // open deliberately across two cold passes and closed on 2026-09-01.
  //
  // run() looks up candidates[0] and every other address in the message was
  // dropped without a word, in a package where every other omission is counted.
  // The lookup bound is unchanged; the silence is what was fixed.
  // ---------------------------------------------------------------------------

  {
    id: "d6-other-addresses-uncounted",
    // Search text updated when F6 turned `skipped` from a COUNT into the LIST,
    // so the notice could name the addresses instead of only counting them.
    find: "    const skipped = [...new Set(candidates.filter((c) => c !== first))];",
    file: "src/provider.ts",
    replace: "    const skipped: string[] = [];",
    why: "the original defect: a message naming five accounts produced a report about one and nothing said the other four existed",
  },
  {
    id: "d6-other-addresses-counted-with-duplicates",
    file: "src/provider.ts",
    find: "    const skipped = [...new Set(candidates.filter((c) => c !== first))];",
    // `slice(1)` rather than the old `candidates.length - 1`. The REPORT path
    // survives this now, because F7 made the renderer remove the address it is
    // reporting on by itself, and the entry moved with that: what it tests is
    // the REFUSAL path, which is the half the renderer cannot do because a
    // refusal has no subject to hand it.
    replace: "    const skipped = candidates.slice(1);",
    why: 'a refusal about BAD in the message "BAD ... A ... BAD" counts and describes the very address it is refusing as one it did not look up. The renderer removes the subject on the report path and has no subject to remove on this one, so `c !== first` is this path\'s only protection',
  },
  {
    id: "d6-threshold-off-by-one",
    file: "src/core/render.ts",
    // Search text updated when F6 replaced the count parameter with the list and
    // the single returned string with an array of lines, and again when F8 made
    // the early return ask about the unreadable-run count too, because a message
    // can hold a run and no further candidate at all.
    find: "  if ((p === null || p.total === 0) && hidden === 0 && !capped) return [];",
    replace: "  if ((p === null || p.total <= 1) && hidden === 0 && !capped) return [];",
    why: "X-006 puts the threshold at ONE: dropping exactly one address is the smallest case that must be reported, and it is the case a comfortable fixture never covers",
  },
  {
    id: "d6-count-dropped-from-the-notice",
    file: "src/core/render.ts",
    // Search text updated when F7 made the count a count of DISTINCT candidates
    // that are not the subject of the report, and said so in the sentence beside
    // it so the number and the words agree.
    find: "      ? `  other_addresses_not_looked_up: ${p.total}. The message held that many further DISTINCT strings shaped like an XRPL address, not counting the one this report is about. Only the FIRST address was looked up; no ledger data was retrieved for any of the rest, so nothing in this report describes them.`",
    replace:
      "      ? `  other_addresses_not_looked_up: some. The message held that many further DISTINCT strings shaped like an XRPL address, not counting the one this report is about. Only the FIRST address was looked up; no ledger data was retrieved for any of the rest, so nothing in this report describes them.`",
    why: "F2's shape applied to the new notice: a count asserted against the whole report is satisfied by any stray digit in the fixture",
  },
  {
    id: "d6-refusal-drops-the-notice",
    file: "src/core/render.ts",
    // Search text updated when F6 gave speak() a multi-line tail, because the
    // notice stopped being one string and became a list of lines, again when
    // F7 lifted the prefix into `head`, and again when F9 moved the whole
    // refusal renderer into src/core/render.ts.
    find: "  const text = `${head}${tail}`;",
    replace: "  const text = head;",
    why: "a refusal about the FIRST address, in a message naming several, reads as an answer about all of them unless the rest are counted out loud",
  },

  // -------------------------------------------------------------------------
  // F1 and F2 from the third cold pass, and the method matters more than the
  // sixteen entries.
  //
  // The first two audits looked for WEAK assertions. This one enumerated from
  // the SOURCE side: every interpolation the package emits into
  // ProviderResult.text, replaced one at a time with a word that could not
  // appear otherwise, suite run, red required. 46 emitted values, 15 survived.
  //
  // Four of the fifteen were not weak assertions. There were NO assertions:
  // `owner_count` and `account_sequence` appeared ZERO times in the suite and
  // in checks/, so the report could have printed anything for either. No
  // test-side reading finds that class, because the population to enumerate is
  // what the code EMITS, not what the tests already mention.
  //
  // The other eleven were all in refusal MESSAGES, which is the only text the
  // model gets when a lookup does not succeed, and which no earlier round had
  // treated as report content at all.
  //
  // Each entry below wordifies one emitted value. `<unavailable>` is preserved
  // where the renderer has that branch, so the mutation changes the NUMBER and
  // nothing else.
  // -------------------------------------------------------------------------
  {
    id: "f1-owner-count-unread",
    file: "src/core/render.ts",
    find: "out.push(`  owner_count: ${renderCount(input?.ownerCount)}`);",
    replace:
      'out.push(`  owner_count: ${renderCount(input?.ownerCount) === "<unavailable>" ? "<unavailable>" : "NINETEEN"}`);',
    why: "owner_count appeared ZERO times in the suite, so the report could print any value for it and stay green",
  },
  {
    id: "f1-account-sequence-unread",
    file: "src/core/render.ts",
    find: "out.push(`  account_sequence: ${renderCount(input?.sequence)}`);",
    replace:
      'out.push(`  account_sequence: ${renderCount(input?.sequence) === "<unavailable>" ? "<unavailable>" : "NINETEEN"}`);',
    why: "account_sequence appeared ZERO times in the suite, same class as owner_count",
  },
  {
    id: "f1-size-cap-denominator-unread",
    file: "src/core/render.ts",
    find: "of the ${rows.length} trust lines that would otherwise",
    replace: "of the NINETEEN trust lines that would otherwise",
    why: "the size-cap notice could read '11 of the NINETEEN' while shown said 14 and returned said 26, and nothing added the three up",
  },
  {
    id: "f1-size-cap-ceiling-unread",
    file: "src/core/render.ts",
    find: "inside its ${BOUNDS.MAX_RENDERED_CHARS} character size cap",
    replace: "inside its NINETEEN character size cap",
    why: "the notice named a character ceiling nothing checked against the bound the report actually respects",
  },
  {
    id: "f1-refusal-fallback-code-unread",
    file: "src/core/result.ts",
    find: 'message: text === "" ? `Refused: ${code}.` : text',
    replace: 'message: text === "" ? `Refused: ZZQQXX.` : text',
    why: "the fallback exists so a blank refusal still names itself, and the one identifying detail in it was read by nothing",
  },
  {
    id: "f1-address-length-unread",
    file: "src/core/address.ts",
    find: "`The XRPL address was ${input.length} characters,",
    replace: "`The XRPL address was NINETEEN characters,",
    why: "the length refusal could quote any number for the string it refused; unreachable through the provider, reachable through the export",
  },
  {
    id: "f1-address-range-min-unread",
    file: "src/core/address.ts",
    find: "outside the valid range of ${MIN_LENGTH} to ${MAX_LENGTH},",
    replace: "outside the valid range of NINETEEN to ${MAX_LENGTH},",
    why: "the quoted lower bound was never checked against the boundary the validator actually enforces",
  },
  {
    id: "f1-address-range-max-unread",
    file: "src/core/address.ts",
    find: "outside the valid range of ${MIN_LENGTH} to ${MAX_LENGTH},",
    replace: "outside the valid range of ${MIN_LENGTH} to NINETEEN,",
    why: "the quoted upper bound was never checked against the boundary the validator actually enforces",
  },
  {
    id: "f1-node-url-protocol-unread",
    file: "src/core/node-url.ts",
    find: "`The XRPL node URL used ${url.protocol} rather than https, so it was refused.`",
    replace: "`The XRPL node URL used ZZQQXX rather than https, so it was refused.`",
    why: "M-4's guard could misreport which scheme it refused, so its output could not be audited",
  },
  {
    id: "f1-node-url-port-unread",
    file: "src/core/node-url.ts",
    find: "`The XRPL node URL used port ${url.port}, which is not on the allowlist, so it was refused.`",
    replace:
      "`The XRPL node URL used port NINETEEN, which is not on the allowlist, so it was refused.`",
    why: "same, for the port half of the allowlist",
  },
  {
    id: "f1-rate-limit-max-unread",
    file: "src/core/ratelimit.ts",
    find: "`This plugin's rate limit of ${BOUNDS.RATE_LIMIT_MAX_REQUESTS} XRPL lookups",
    replace: "`This plugin's rate limit of NINETEEN XRPL lookups",
    why: "provider-reachable on the eleventh lookup in a window; the number an operator reads as 'how many am I allowed' was pinned by nothing",
  },
  {
    id: "f1-rate-limit-window-unread",
    file: "src/core/ratelimit.ts",
    find: "XRPL lookups per ${seconds} seconds has been reached",
    replace: "XRPL lookups per NINETEEN seconds has been reached",
    why: "the number an operator reads as 'how long do I wait', in seconds, against a window held in milliseconds",
  },
  {
    id: "f1-http-status-unread",
    file: "src/transport/client.ts",
    find: "`The XRPL node answered with HTTP ${res.status}, so no ledger data was retrieved.`",
    replace: "`The XRPL node answered with HTTP NINETEEN, so no ledger data was retrieved.`",
    why: "provider-reachable on any non-200; the only diagnostic in the message could be any fixed string",
  },
  {
    id: "f1-request-timeout-unread",
    file: "src/transport/client.ts",
    find: "? `The XRPL node did not answer within ${timeoutMs}ms,",
    replace: "? `The XRPL node did not answer within NINETEENms,",
    why: "provider-reachable on every timeout; the reported wait was never compared to the wait actually configured",
  },
  {
    id: "f1-outer-catch-error-name-unread",
    file: "src/provider.ts",
    find: '    const name: unknown = error.name;\n    return typeof name === "string" ? name : "unknown error";',
    replace: '    void error;\n    return "ZZQQXX";',
    why: "invariant 1's last line of defence had a test proving it SPEAKS and none reading what it said",
  },
  {
    id: "f2-duplicate-later-address-counted-twice",
    file: "src/provider.ts",
    // Search text updated when F6 turned `skipped` into the LIST. The mutation
    // is the same one: the dedupe removed, the filter kept. What it tests moved
    // in F7, because the renderer now de-duplicates what it PRINTS: the dedupe
    // here is what keeps the CACHE KEY canonical.
    find: "    const skipped = [...new Set(candidates.filter((c) => c !== first))];",
    replace: "    const skipped = candidates.filter((c) => c !== first);",
    why: '"A and B" and "A and B and B" render to the identical report, so they must share one cache entry. Without the dedupe their digests differ, the two land on different keys, and the cache stops serving a turn whose answer it is already holding',
  },

  // -------------------------------------------------------------------------
  // The tree-integrity precondition, and this one is not a class this repo
  // reasoned its way to. It happened.
  //
  // An interrupted `git commit` killed the pre-commit hook, which killed THIS
  // script between writing a mutation and restoring it. The restore is in a
  // `finally`, and a `finally` does not survive a hard kill.
  // src/core/response.ts was left holding `if (false && ...)` across the guard
  // that turns rippled's HTTP-200-with-an-error-body into ACCOUNT_NOT_FOUND.
  // The next commit caught it only because the hook happened to run.
  //
  // Every entry below reintroduces a way the new guard could fail OPEN, which
  // is the only way it fails that matters: a precondition that passes a
  // poisoned tree is worse than none, because the run then prints "all files
  // restored byte-identical" over a baseline it adopted from the poisoning.
  // -------------------------------------------------------------------------
  {
    id: "tree-sentinel-unreadable-reads-as-absent",
    file: "checks/tree_sentinel.ts",
    find: '    return { state: "unreadable", why: "not valid JSON" };',
    replace: '    return { state: "absent" };',
    why: "a half-written sentinel is exactly what a killed process leaves, so reading a parse failure as 'no sentinel' fails open in the one case the guard exists for",
  },
  {
    id: "tree-sentinel-empty-target-list-accepted",
    file: "checks/tree_sentinel.ts",
    find: "  if (!Array.isArray(raw.targets) || raw.targets.length === 0) {",
    replace: "  if (!Array.isArray(raw.targets)) {",
    why: "a sentinel listing no targets can detect no drift, so accepting it as well-formed produces a guard that always reports the tree intact",
  },
  {
    id: "tree-sentinel-drift-unreported",
    file: "checks/tree_sentinel.ts",
    find: "    if (hashOf(t.file) !== t.sha256) drifted.push(t.file);",
    replace: "    if (false && hashOf(t.file) !== t.sha256) drifted.push(t.file);",
    why: "the refusal still fires but names nothing, so a human is told a run was interrupted and given no file to look at",
  },
  {
    id: "tree-sentinel-vanished-file-counts-as-intact",
    file: "checks/tree_sentinel.ts",
    find: "    if (hashOf(t.file) !== t.sha256) drifted.push(t.file);",
    replace:
      "    const __h = hashOf(t.file);\n    if (__h !== null && __h !== t.sha256) drifted.push(t.file);",
    why: "a file the harness was mid-way through rewriting can be unreadable, and 'I cannot see it' is not 'it is fine'",
  },
  {
    id: "tree-sentinel-cleared-after-failed-restore",
    file: "checks/tree_sentinel.ts",
    find: "  return dirtyFileCount === 0;",
    replace: "  return true;",
    why: "clearing the sentinel after a restore that FAILED hands the next run a poisoned tree with nothing left to warn it, which is the incident all over again one step later",
  },

  // -------------------------------------------------------------------------
  // The WIRING of the precondition, which is a different thing from the
  // precondition working.
  //
  // The first version of those tests asserted the call EXISTS and comes before
  // the snapshot. `staleSentinelRefusal(ROOT);` on a line of its own satisfies
  // both and refuses nothing: the guard runs, computes the right answer, and
  // drops it. A checked value that nothing acts on is the same shape as a
  // count nothing reads, one layer out from F1.
  //
  // Six entries, three shapes across both scripts, because a rule enforced by
  // one sweep over two files is a rule nobody notices losing a file. This repo
  // has already paid for that: the invisible-character rule was absolute and
  // its enforcement covered eight of the ten files it applied to.
  //
  // A side effect worth knowing: naming check.ts and checks/mutations.ts here
  // puts them in TARGETS, so the sentinel now records and watches the two
  // scripts that run the gate, not just the source they grade.
  // -------------------------------------------------------------------------
  {
    id: "gate-refusal-result-discarded",
    file: "check.ts",
    find: "const stale = staleSentinelRefusal(ROOT);",
    replace: "staleSentinelRefusal(ROOT);\nconst stale = null;",
    why: "the gate computes the refusal and drops it, which passes any assertion that only asks whether the call is there",
  },
  {
    id: "gate-refusal-test-inverted",
    file: "check.ts",
    find: "if (stale !== null) {",
    replace: "if (stale === null) {",
    why: "binds, tests and exits, and blocks a CLEAN tree while sailing straight past a poisoned one",
  },
  {
    id: "gate-refusal-does-not-exit",
    file: "check.ts",
    find: 'GATE REFUSED TO START. Nothing was measured.");\n  process.exit(1);',
    replace: 'GATE REFUSED TO START. Nothing was measured.");',
    why: "prints the refusal and then measures the tree anyway, which is the warn-and-carry-on shape that reads as a control and is not one",
  },
  // These two anchors span TWO LINES, and that is not style. This file is the
  // only target that quotes its own targets: `find: "if (staleTree !== null) {"`
  // is itself a line of this file, so the single-line anchor matched twice and
  // the harness correctly called it STALE. A real newline cannot appear inside
  // the quotation, where it is stored as a backslash and an n, so a two-line
  // span is unambiguous. Measured before it was written, not after it broke.
  {
    id: "harness-refusal-result-discarded",
    file: "checks/mutations.ts",
    find: "const staleTree = staleSentinelRefusal(ROOT);\nif (staleTree !== null) {",
    replace: "staleSentinelRefusal(ROOT);\nconst staleTree = null;\nif (staleTree !== null) {",
    why: "the harness computes the refusal and drops it, then snapshots a poisoned file as the original",
  },
  {
    id: "harness-refusal-test-inverted",
    file: "checks/mutations.ts",
    find: "if (staleTree !== null) {\n  console.log(staleTree);",
    replace: "if (staleTree === null) {\n  console.log(staleTree);",
    why: "refuses on a clean tree and grades every entry in this file against a poisoned one",
  },
  {
    id: "harness-refusal-does-not-exit",
    file: "checks/mutations.ts",
    find: 'A poisoned baseline grades nothing.");\n  process.exit(1);',
    replace: 'A poisoned baseline grades nothing.");',
    why: "warns, then snapshots the poisoned tree anyway and prints all files restored byte-identical over the top",
  },

  // -------------------------------------------------------------------------
  // A FOURTH cold pass, which DISPROVED the wiring assertion above by building
  // two check.ts files that satisfy it while the gate never calls the guard.
  // Both were measured end to end, not argued: full suite green, and the gate
  // running five steps over a poisoned tree instead of refusing to start.
  //
  // The shape behind all three fixes is one sentence. The assertion was reading
  // the file for a SHAPE and calling that a control, and a shape can be written
  // down without being run. Three ways it can be:
  //
  //   quoted as a regex   codeOnly blanked comments and strings and knew
  //                       nothing about regex literals, so a third notation for
  //                       the same characters read straight through as code.
  //   defined not called  the guard moved into an exported function with no
  //                       call site. tsc, biome and 283 tests all green.
  //   located by prose    the ordering anchored on the first mention anywhere
  //                       in the file, and checks/mutations.ts mentions the
  //                       call in a comment at line 810 and makes it at 902.
  //
  // Stated per script rather than swept over both, for the reason the entries
  // above give: a rule enforced by one loop over two files is a rule nobody
  // notices losing a file.
  // -------------------------------------------------------------------------
  {
    id: "wiring-regex-quotation-reads-as-code",
    file: "src/__tests__/tree-sentinel.test.ts",
    find: "        if (regexAllowed) {",
    replace: "        if (false) {",
    why: "with regex literals no longer blanked, a file that only QUOTES the wiring as two patterns satisfies the assertion, which is how a cold pass got the gate to run five steps over a poisoned tree",
  },
  {
    id: "gate-guard-moved-into-a-function",
    file: "check.ts",
    find: 'const stale = staleSentinelRefusal(ROOT);\nif (stale !== null) {\n  console.log(stale);\n  console.log("\\nGATE REFUSED TO START. Nothing was measured.");\n  process.exit(1);\n}',
    replace:
      'export function refuseIfTreeIsStale(): void {\n  const stale = staleSentinelRefusal(ROOT);\n  if (stale !== null) {\n    console.log(stale);\n    console.log("\\nGATE REFUSED TO START. Nothing was measured.");\n    process.exit(1);\n  }\n}',
    why: "every line of the guard present, correct and above the first step, inside a function with no call site. Measured: tsc, biome and the whole suite stayed green and the gate did not refuse",
  },
  {
    id: "harness-guard-moved-into-a-function",
    file: "checks/mutations.ts",
    find: 'const staleTree = staleSentinelRefusal(ROOT);\nif (staleTree !== null) {\n  console.log(staleTree);\n  console.log("\\nmutations: REFUSED TO START. A poisoned baseline grades nothing.");\n  process.exit(1);\n}',
    replace:
      'export function refuseIfTheTreeIsStale(): void {\n  const staleTree = staleSentinelRefusal(ROOT);\n  if (staleTree !== null) {\n    console.log(staleTree);\n    console.log("\\nmutations: REFUSED TO START. A poisoned baseline grades nothing.");\n    process.exit(1);\n  }\n}',
    why: "the same defined-but-never-called shape in the harness, where it would snapshot a poisoned file as the original",
  },
  {
    id: "gate-refusal-after-the-first-step",
    file: "check.ts",
    find: "const stale = staleSentinelRefusal(ROOT);",
    replace:
      "for (const step of STEPS) {\n  void step;\n}\nconst stale = staleSentinelRefusal(ROOT);",
    why: "the guard still binds, tests and exits, and now runs AFTER the steps it is a precondition for, which is the ordering an anchor on the first mention in the file cannot see",
  },
  {
    id: "harness-refusal-after-the-snapshot",
    file: "checks/mutations.ts",
    find: "const staleTree = staleSentinelRefusal(ROOT);\nif (staleTree !== null) {",
    replace:
      'for (const f of TARGETS) ORIGINAL.set(f, readFileSync(join(ROOT, f), "utf8"));\nconst staleTree = staleSentinelRefusal(ROOT);\nif (staleTree !== null) {',
    why: "THE ordering that matters: snapshot first and a leftover mutation becomes the original the run restores TO. This survived while the assertion anchored on a comment at line 810",
  },

  // -------------------------------------------------------------------------
  // Three decisions inside checks/tree_sentinel.ts that a SOURCE-side
  // enumeration of that file found had no test at all. The shipped behaviour
  // was right in all three; nothing held it there. Every one is a fail-open:
  // the guard reporting "no run was interrupted" when one was.
  //
  // n7 from the same enumeration is deliberately NOT here. Accepting a target
  // with an empty recorded hash makes every target read as drifted, so it
  // degrades the message rather than failing open, and it still survives.
  // Recorded so the next pass does not rediscover it as new.
  // -------------------------------------------------------------------------
  {
    id: "tree-sentinel-empty-file-reads-as-absent",
    file: "checks/tree_sentinel.ts",
    find: '  if (!existsSync(path)) return { state: "absent" };',
    replace:
      '  if (!existsSync(path) || readFileSync(path, "utf8").trim() === "") return { state: "absent" };',
    why: "writeFileSync truncates before it writes, so zero bytes is exactly what the kill this module exists for leaves behind, and reading that as no sentinel is the fail-open",
  },
  {
    id: "tree-sentinel-read-error-reads-as-absent",
    file: "checks/tree_sentinel.ts",
    find: '    return { state: "unreadable", why: "the file exists and could not be read" };',
    replace: '    return { state: "absent" };',
    why: "readSentinel's catch branch, which nothing had ever reached: a sentinel that exists and cannot be read is not a sentinel that is not there",
  },
  {
    id: "tree-sentinel-refusal-suppressed-when-nothing-drifted",
    file: "checks/tree_sentinel.ts",
    find: "  return describeStaleSentinel(state.sentinel, drifted, path);",
    replace:
      "  return drifted.length === 0 ? null : describeStaleSentinel(state.sentinel, drifted, path);",
    why: "the composed guard reading as an all clear. The property was asserted on describeStaleSentinel and not on staleSentinelRefusal, which is the function both scripts actually call",
  },

  // -------------------------------------------------------------------------
  // The publish workflow. npm attaches a provenance attestation only when four
  // things hold, and it does not fail loudly on all four, so a publish with no
  // attestation looks exactly like one with a good attestation. That is the
  // same shape as every other entry in this file: a control that reports on its
  // own behalf.
  //
  // Two of these break the workflow in ways that a naive reader would MISS,
  // which is the point. `id-token-commented-out` leaves every character of the
  // permission in the file and grants nothing; `provenance-on-the-command-line`
  // adds a flag that looks like belt and braces and is a second source for one
  // setting. Both are caught only because the test reads the file with comments
  // stripped and reads the parsed run commands rather than the raw text.
  // -------------------------------------------------------------------------
  {
    id: "workflow-id-token-downgraded",
    file: ".github/workflows/publish.yml",
    find: "  id-token: write",
    replace: "  id-token: read",
    why: "no OIDC token to sign with, so npm publishes successfully and silently attaches no attestation",
  },
  {
    id: "workflow-id-token-commented-out",
    file: ".github/workflows/publish.yml",
    find: "  id-token: write",
    replace: "  # id-token: write",
    why: "every character of the permission still in the file, granting nothing. A grep for the shape passes; the workflow has no token",
  },
  {
    id: "workflow-self-hosted-runner",
    file: ".github/workflows/publish.yml",
    find: "runs-on: ubuntu-latest",
    replace: "runs-on: self-hosted",
    why: "provenance requires a CLOUD-HOSTED runner. A self-hosted one runs the whole job green and produces nothing",
  },
  {
    id: "workflow-verify-after-publish",
    file: ".github/workflows/publish.yml",
    find: "      - name: Verify\n        run: bun run verify\n\n      - name: Publish\n        run: npm publish --access public",
    replace:
      "      - name: Publish\n        run: npm publish --access public\n\n      - name: Verify\n        run: bun run verify",
    why: "both steps present, both green, and the gate now runs AFTER the one-way door. This is the ordering a check anchored on text position cannot see, because the file discusses publishing above the verify step",
  },
  {
    id: "workflow-verify-step-removed",
    file: ".github/workflows/publish.yml",
    find: "      - name: Verify\n        run: bun run verify\n\n",
    replace: "",
    why: "the other way the gate stops guarding the door: not reordered, gone. prepublishOnly would still fire, so nothing in the workflow output would look wrong",
  },
  {
    id: "workflow-provenance-on-the-command-line",
    file: ".github/workflows/publish.yml",
    find: "        run: npm publish --access public",
    replace: "        run: npm publish --access public --provenance",
    why: "two sources for one setting, and it reads as belt and braces. They can disagree, and package.json is the one a consumer can inspect",
  },

  // -------------------------------------------------------------------------
  // Authentication, which is a different subject from attestation and arrived
  // later. npm now authenticates this workflow as a registered trusted
  // publisher, so the first two below reintroduce a REQUIREMENT that has become
  // a regression: the registry token this file used to carry. The old path died
  // on EOTP every time, because a granular access token cannot answer npm's 2FA
  // challenge, and OIDC can.
  //
  // The job-level one is the one worth naming. It authenticates the publish
  // exactly as the step-level env did, and a check that reads only the publish
  // step reports nothing about it.
  //
  // The last three are the npm floor. Trusted publishing needs npm 11.5.1, the
  // runner decides what npm it has, and no test in this repo can see the runner.
  // What is testable is that the workflow raises it and then REFUSES below the
  // floor, which is why one of these deletes only the `exit 1` and leaves a
  // check that still runs and still prints and no longer stops anything.
  // -------------------------------------------------------------------------
  {
    id: "workflow-npm-token-reintroduced",
    file: ".github/workflows/publish.yml",
    find: "        run: npm publish --access public",
    replace:
      "        run: npm publish --access public\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
    why: "the credential path back in the step it used to live in. A standing long-lived secret in a repo that no longer needs to hold one, publishing by a route the trusted publisher configuration never authorised",
  },
  {
    id: "workflow-npm-token-at-job-level",
    file: ".github/workflows/publish.yml",
    find: "    runs-on: ubuntu-latest",
    replace:
      "    runs-on: ubuntu-latest\n    env:\n      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
    why: "the same credential one level up, where a check that reads only the publish step cannot see it. Every step in the job receives it and the publish authenticates exactly as it used to",
  },
  {
    id: "workflow-npm-raise-removed",
    file: ".github/workflows/publish.yml",
    find: '          npm install -g "npm@^$MIN"\n',
    replace: "",
    why: "the npm version left to whatever the runner happens to ship. Below 11.5.1 there is no trusted publishing, and with no token either, the job reaches the registry with nothing to authenticate with, after the gate has already run",
  },
  {
    id: "workflow-npm-floor-refusal-removed",
    file: ".github/workflows/publish.yml",
    find: "            exit 1\n",
    replace: "",
    why: "the version check still runs, still prints its complaint, and no longer fails the job. A guard that reports instead of acting, which is the shape this entire file exists to catch",
  },
  {
    id: "workflow-npm-floor-lowered",
    file: ".github/workflows/publish.yml",
    find: "          MIN=11.5.1",
    replace: "          MIN=11.0.0",
    why: "the floor moved below what npm requires, so the check passes on an npm that cannot do trusted publishing at all. The step still exists and still refuses something, just not the thing that decides whether this works",
  },
  {
    id: "package-repository-case-drifted",
    file: "package.json",
    find: '"url": "git+https://github.com/nctrnlsoul/plugin-ns-xrpl.git"',
    replace: '"url": "git+https://github.com/NctrnlSoul/plugin-ns-xrpl.git"',
    why: "npm compares repository against the publishing repo CASE-SENSITIVELY. A case-only drift passes every toLowerCase comparison and fails at the registry, after the gate is green and the tag is already pushed",
  },
  {
    id: "package-provenance-disabled",
    file: "package.json",
    find: '"provenance": true',
    replace: '"provenance": false',
    why: "the workflow is correct in every respect and nothing asks for an attestation. The publish succeeds and the package ships without one",
  },
  // -------------------------------------------------------------------------
  // THE STAGE-1 FLAG, AND THE IN-TURN CACHE IT MADE NECESSARY.
  //
  // The flag is one line and it is the only thing putting this provider's report
  // into the stage-1 response state, whichever contexts a turn selects. The cache
  // is what stops that guarantee being paid for with two network reads of
  // identical data on a turn that asks twice.
  //
  // Half of the cache is a PARTITION KEY, so half of the entries below are the
  // key admitting something it cannot safely partition on. A key is not a
  // performance detail: the wrong one serves one agent's lookup to another, or
  // serves a report whose omission notice belongs to a different message.
  // -------------------------------------------------------------------------
  {
    id: "always-in-response-state-removed",
    file: "src/provider.ts",
    find: "    alwaysInResponseState: true,",
    replace: "    alwaysInResponseState: false,",
    why: "without the flag the report is absent from the stage-1 prompt and no lookup runs during stage 1, so whether the model ever sees it depends on which contexts the turn selects. The flag's one guarantee is gone and nothing reports that",
  },
  {
    id: "always-in-response-state-cancelled-by-private",
    file: "src/provider.ts",
    find: "    alwaysInResponseState: true,",
    replace: "    alwaysInResponseState: true,\n    private: true,",
    why: "alwaysOnResponseStateProviderNames requires !provider.private, so private cancels the flag and the runtime says nothing when it does",
  },
  {
    id: "cache-serves-stale-entry",
    file: "src/core/turncache.ts",
    find: "  return age >= 0 && age <= BOUNDS.TURN_CACHE_TTL_MS;",
    replace: "  return age >= 0;",
    why: "an entry with no expiry outlives the turn that produced it, and a balance read minutes ago is served as the current one",
  },
  {
    id: "cache-serves-negative-age",
    file: "src/core/turncache.ts",
    find: "  return age >= 0 && age <= BOUNDS.TURN_CACHE_TTL_MS;",
    replace: "  return age <= BOUNDS.TURN_CACHE_TTL_MS;",
    why: "the one-sided form is true for every negative age, so an entry written under a clock that later runs backwards is immortal, and deps.now() is injectable",
  },
  {
    id: "cache-key-drops-agent-id",
    file: "src/core/turncache.ts",
    // Search text updated when F7 replaced the stringified skipped COUNT with
    // the digest of the skipped LIST, which is already a string.
    find: "  return [input.agentId, input.messageId, input.address, skipped].join(TURN_CACHE_KEY_SEPARATOR);",
    replace: "  return [input.messageId, input.address, skipped].join(TURN_CACHE_KEY_SEPARATOR);",
    why: "the provider is a module-level singleton, so one cache serves every agent in the process, and without the agent id one agent reads another agent's lookup",
  },
  {
    id: "cache-key-drops-the-skipped-digest",
    file: "src/core/turncache.ts",
    // Renamed from cache-key-drops-skipped-count when the component stopped
    // being a count. The defect is the same one and it got larger: the report
    // now NAMES the skipped addresses, so a key that carries nothing about them
    // serves a report naming an account the second message never held.
    find: "  return [input.agentId, input.messageId, input.address, skipped].join(TURN_CACHE_KEY_SEPARATOR);",
    replace:
      "  return [input.agentId, input.messageId, input.address].join(TURN_CACHE_KEY_SEPARATOR);",
    why: "invariant 10 through the cache: two reports differ by exactly the other-address lines, so a key without them serves a shortened report that reads as a complete one, and one that NAMES an address the message never held",
  },
  {
    id: "skipped-digest-ignores-the-identities",
    file: "src/core/turncache.ts",
    // Search text updated when F8 hashed the unreadable-run count into the same
    // component, and again at F10 when the two scalars moved into `scalars` so
    // no line ran past the formatter's width. The mutation is unchanged both
    // times: the identities erased, everything else kept.
    find: "      `${scalars}${TURN_CACHE_KEY_SEPARATOR}${candidates.join(TURN_CACHE_KEY_SEPARATOR)}`,",
    replace: "      `${scalars}${TURN_CACHE_KEY_SEPARATOR}${String(candidates.length)}`,",
    why: "the count form wearing the digest's clothes: same shape, same length, and two same-length lists with different members still collide, which is the exact collision that served one turn's address names to another turn",
  },
  {
    id: "skipped-digest-drops-the-separator",
    file: "src/core/turncache.ts",
    // Search text updated at F10 with the entry above, for the same reason.
    find: "      `${scalars}${TURN_CACHE_KEY_SEPARATOR}${candidates.join(TURN_CACHE_KEY_SEPARATOR)}`,",
    replace: '      `${scalars}${candidates.join("")}`,',
    why: 'without a separator ["ab","c"] and ["a","bc"] concatenate to one string and one digest, so two different messages read each other\'s report. NUL cannot occur in Ripple base58, which is what makes the boundary unforgeable',
  },
  {
    id: "skipped-digest-admits-a-non-string-entry",
    file: "src/core/turncache.ts",
    find: '    if (typeof c !== "string") return null;',
    replace: '    if (typeof c !== "string") continue;',
    why: "a non-string entry cannot be rendered and cannot be compared as one, so digesting it keys on a coercion. Null is the safe direction: no key means the real work runs twice, which is the behaviour this module removes rather than one it breaks",
  },
  {
    id: "cache-key-admits-any-skipped-shape",
    file: "src/core/turncache.ts",
    find: '  if (typeof skipped !== "string" || !SKIPPED_DIGEST_PATTERN.test(skipped)) return null;',
    replace: '  if (typeof skipped !== "string") return null;',
    why: "the shape test is what refuses a component that is not a digest at all. Without it any string partitions the cache, so a caller handing over a count, an empty string or a truncated digest gets a key that means something other than what it says",
  },
  {
    id: "cache-admits-missing-message-id",
    file: "src/core/turncache.ts",
    find: "  if (!isUuidLike(input.messageId)) return null;",
    replace: "  if (input.messageId === null) return null;",
    why: "Memory.id is declared optional, so an absent id is a real input. Admitted, every id-less message in the process shares one partition",
  },
  {
    id: "cache-admits-non-uuid-id",
    file: "src/core/turncache.ts",
    find: "  if (!isUuidLike(input.messageId)) return null;",
    replace: '  if (typeof input.messageId !== "string") return null;',
    why: "UUID is an unbranded string, so any string is a real input. Admitted, a caller picks which partition to read by naming it",
  },
  {
    id: "cache-read-ignores-nonfinite-clock",
    file: "src/core/turncache.ts",
    find: "  if (!Number.isFinite(input.now)) return null;",
    replace: "  if (false) return null;",
    why: "checkRateLimit fails CLOSED on a non-finite clock, and a key built on one puts a cache read in front of a limiter that would have refused",
  },
  {
    id: "cache-checked-after-ratelimit",
    file: "src/provider.ts",
    // Search text updated when F8 gave speak() its unreadable-run count.
    find: '    // A hit returns HERE, before the rate limiter. A turn that already paid for\n    // its lookup must not be refused for asking about it a second time.\n    const cached = readTurnCache(turnCache, key, now);\n    if (cached !== null) {\n      return {\n        text: cached.text,\n        values: { ...cached.values },\n        data: { ...cached.data, xrplCache: "hit" },\n      };\n    }\n\n    const limit = checkRateLimit(stamps, now);\n    // NEVER stored. This message asserts a fact about now, that the limit "has\n    // been reached", so replaying it after the window reopened would be a false\n    // statement in report content, and a refusal message is the only text the\n    // model gets when a lookup fails.\n    if (!limit.ok) return speak(limit, allNamed, hidden, cacheState);',
    replace:
      '    const limit = checkRateLimit(stamps, now);\n    if (!limit.ok) return speak(limit, allNamed, hidden, cacheState);\n\n    const cached = readTurnCache(turnCache, key, now);\n    if (cached !== null) {\n      return {\n        text: cached.text,\n        values: { ...cached.values },\n        data: { ...cached.data, xrplCache: "hit" },\n      };\n    }',
    why: "a turn that already paid for its lookup is refused for asking a second time, so the router gets a report and the planner gets a rate-limit refusal inside one turn",
  },
  {
    id: "cache-caches-rate-limited",
    file: "src/provider.ts",
    find: "    if (!limit.ok) return speak(limit, allNamed, hidden, cacheState);",
    replace: "    if (!limit.ok) return remember(speak(limit, allNamed, hidden, cacheState));",
    why: "the message asserts a fact about NOW, that the limit has been reached. Replayed after the window reopens it is a false statement in the only text the model gets",
  },
  {
    id: "cache-caches-address-malformed",
    file: "src/provider.ts",
    find: '    if (!address.ok) return speak(address, allNamed, hidden, "not-cacheable");',
    replace:
      '    if (!address.ok) {\n      const t = deps.now();\n      const k = turnCacheKey({\n        agentId: runtime?.agentId,\n        messageId: message?.id,\n        address: first,\n        skipped,\n        now: t,\n      });\n      const c = readTurnCache(turnCache, k, t);\n      if (c !== null) {\n        return { text: c.text, values: { ...c.values }, data: { ...c.data, xrplCache: "hit" } };\n      }\n      const spoken = speak(address, allNamed, hidden, "miss");\n      writeTurnCache(turnCache, k, spoken, t);\n      return spoken;\n    }',
    why: "nothing read the ledger, so there is nothing a later call could legitimately replay, and it keys the cache on an UNVALIDATED candidate string",
  },
  {
    id: "cache-evicts-on-read-not-insert",
    file: "src/core/turncache.ts",
    find: "  });\n  evictTurnCache(cache, now);\n}\n\n/**\n * Serve one turn's stored result, or null.\n *\n * Every unknown is a miss AND a delete. A cache is the one place where falling\n * through to the real work is always safe, so nothing here has to guess what a\n * malformed entry was supposed to mean.\n */\nexport function readTurnCache(\n  cache: TurnCache,\n  key: string | null,\n  now: number,\n): CachedResult | null {\n  if (key === null) return null;\n",
    replace:
      "  });\n}\n\n/** Serve one turn's stored result, or null. */\nexport function readTurnCache(\n  cache: TurnCache,\n  key: string | null,\n  now: number,\n): CachedResult | null {\n  if (key === null) return null;\n  evictTurnCache(cache, now);\n",
    why: "insert is the only path that grows the map. Evicting on read leaves a burst of writes with no reads between them unbounded, and that burst is what a flood of turns looks like",
  },
  {
    id: "cache-unbounded",
    file: "src/core/turncache.ts",
    find: "  while (cache.size > BOUNDS.TURN_CACHE_MAX_ENTRIES) {",
    replace: "  while (false && cache.size > BOUNDS.TURN_CACHE_MAX_ENTRIES) {",
    why: "H-2 one layer in: an uncapped map of rendered reports grows for as long as turns keep arriving",
  },
  {
    id: "cache-returns-shared-reference",
    file: "src/core/turncache.ts",
    find: "  return { text: held.text, values: { ...held.values }, data: { ...held.data } };",
    replace: "  return { text: held.text, values: held.values, data: held.data };",
    why: "a consumer that mutates its result rewrites what every later hit on that key serves",
  },
  {
    id: "cache-ttl-below-lookup-budget",
    file: "src/core/bounds.ts",
    find: "  TURN_CACHE_TTL_MS: 30_000,",
    replace: "  TURN_CACHE_TTL_MS: 10_000,",
    why: "a TTL under TOTAL_LOOKUP_BUDGET_MS expires on exactly the slow turns the cache exists for: the entry is gone before the second call of the same turn asks for it",
  },
  // -------------------------------------------------------------------------
  // WHAT A COLD ADVERSARIAL PASS GOT PAST THE ENTRIES ABOVE.
  //
  // Six of its own hand-applied mutations SURVIVED a fully green suite, and
  // the shape is this file's oldest lesson rather than a new one: a guard
  // pinned by a test that cannot fail is pinned by nothing. The write-guard
  // test wrote into an EMPTY cache and asserted the size stayed zero, which
  // is true with the guard and true without it, because the bad entry is
  // written and then immediately swept.
  //
  // Two of these are not weak tests but a real defect the pass found: the
  // entry was stamped with the clock read BEFORE the network, which charged
  // network time to the TTL and let a slow turn's sweep delete a faster
  // turn's live entry. Two more are guards that had NO test at all, one file
  // out: the public re-export a consumer depends on, and the fail-open
  // lint's own hand-maintained file list.
  // -------------------------------------------------------------------------
  {
    id: "cache-stamped-with-the-pre-network-clock",
    file: "src/provider.ts",
    find: "      writeTurnCache(turnCache, key, result, writtenAt);",
    replace: "      writeTurnCache(turnCache, key, result, now);",
    why: "the clock from BEFORE the first request charges the whole network time to the TTL, and hands the sweep a clock older than entries other turns wrote while this one was in flight. isFresh is two-sided, so a slow turn completing deletes a live entry belonging to a different turn",
  },
  {
    id: "cache-write-clock-throw-discards-the-report",
    file: "src/provider.ts",
    find: "      let writtenAt: number;\n      try {\n        writtenAt = deps.now();\n      } catch {\n        // A clock that throws is not a reason to discard a report that already\n        // came back from the ledger. Not caching is this module's safe direction\n        // everywhere else and it is the safe direction here: the next call does\n        // the real work. Nothing about the report itself is in doubt.\n        return result;\n      }\n",
    replace: "      const writtenAt = deps.now();\n",
    why: "the write-time stamp is a SECOND call to deps.now(). A throw escaping it turns a lookup that already succeeded against the ledger into an INTERNAL_ERROR refusal, which is the cache failing the lookup",
  },
  {
    id: "silent-result-is-a-shared-singleton",
    file: "src/provider.ts",
    find: 'function silent(): SpokenResult {\n  return { text: "", values: {}, data: { ok: true, attempted: false, xrplCache: "not-cacheable" } };\n}',
    replace:
      'const SHARED_SILENT: SpokenResult = {\n  text: "",\n  values: {},\n  data: { ok: true, attempted: false, xrplCache: "not-cacheable" },\n};\nfunction silent(): SpokenResult {\n  return SHARED_SILENT;\n}',
    why: "the no-address path runs on every message the agent sees, so one shared object reaches every consumer in the process and one write to its values rewrites what every later silent turn returns",
  },
  {
    id: "cache-write-admits-nonfinite-clock",
    file: "src/core/turncache.ts",
    find: "  if (key === null || !Number.isFinite(now)) return;",
    replace: "  if (key === null) return;",
    why: "the NaN-stamped entry is written and then swept by evictTurnCache(cache, NaN), and no age compares true against NaN, so ONE non-finite clock reading wipes every entry in the process on its way past",
  },
  {
    id: "cache-write-admits-null-key",
    file: "src/core/turncache.ts",
    find: "  if (key === null || !Number.isFinite(now)) return;",
    replace: "  if (!Number.isFinite(now)) return;",
    why: "Map accepts a null key, so the entry is stored where readTurnCache returns early and can never reach it: dead weight counting against the bound and evicting live entries",
  },
  {
    id: "cache-eviction-freshness-one-sided",
    file: "src/core/turncache.ts",
    find: "    if (!isFresh(entry.storedAt, now)) cache.delete(key);",
    replace: "    if (now - entry.storedAt > BOUNDS.TURN_CACHE_TTL_MS) cache.delete(key);",
    why: "Date.now() is not monotonic and one NTP step backwards leaves an entry stamped in the future. The read refuses it on sight; a sweep that only looks for entries too OLD keeps it forever, holding a slot nothing can be served from",
  },
  {
    id: "cache-entry-storedat-type-unchecked",
    file: "src/core/turncache.ts",
    find: '  if (typeof held.storedAt !== "number") {',
    replace: "  if (false) {",
    why: 'the arithmetic coerces: `now - "1000"` is a real number, so a string stamp reaches isFresh and reads as fresh. This is the half of that guard that can change a result, which is why the non-finite half was removed rather than kept',
  },
  {
    id: "index-drops-turncache-exports",
    file: "src/index.ts",
    // Search text updated when F7 exported skippedDigest beside isUuidLike, for
    // the reason the header of that module gives: a predicate the key builder
    // depends on lives where a test can reach it directly.
    find: 'export {\n  type CachedResult,\n  type CachedScalar,\n  createTurnCache,\n  isUuidLike,\n  readTurnCache,\n  skippedDigest,\n  TURN_CACHE_KEY_SEPARATOR,\n  type TurnCache,\n  type TurnCacheEntry,\n  type TurnCacheKeyInput,\n  turnCacheKey,\n  writeTurnCache,\n} from "./core/turncache.ts";',
    replace: "",
    why: "every test imports ../core/turncache.ts directly, so losing the re-export is invisible to the suite and total for a consumer, which has the package entry point and nothing else",
  },
  {
    id: "failopen-lint-drops-turncache",
    file: "checks/failopen_lint.ts",
    find: '  "src/core/turncache.ts",\n',
    replace: "",
    why: "DECIDING_FILES is a hand-maintained array, and the gate stays GREEN reporting 'clean across 9 deciding files' while the newest deciding module is read for nothing but invisible characters",
  },
  {
    id: "failopen-lint-drops-transport",
    file: "checks/failopen_lint.ts",
    find: '  "src/transport/client.ts",\n',
    replace: "",
    why: "the array's comment states the rule as every module under src/core PLUS the transport and the provider, and the test enforced only the src/core third of it. The transport is where the response body arrives, so it is the last place a coercion should go unread",
  },

  // -------------------------------------------------------------------------
  // F6. WHAT A REAL MODEL DID WITH A COUNT.
  //
  // D6 stopped this package dropping the second address in a message in silence.
  // Published 0.1.1 was then run against llama3.2 3B on elizaOS core
  // 2.0.3-beta.7. A message named TWO valid addresses. The report described the
  // first and emitted the aggregate notice verbatim into the prompt:
  // "other_addresses_not_looked_up: 1 ... so nothing in this report describes
  // them." The model answered with a balance for BOTH, inventing 0 XRP for an
  // account that holds 267,875. A different turn, where the report ADDRESSED an
  // account by name and stated data was absent for it, invented nothing.
  //
  // So the finding is not that the omission was unspoken. It was spoken, with a
  // count, exactly as invariant 10 demands. The finding is that SILENCE ABOUT A
  // NAMED ENTITY is the hazard, and a count is not a name.
  //
  // Every entry below is a way the naming could go back to being a count, or a
  // way the naming itself could become the injection it replaced. The second
  // half is the reason the checksum gate exists: the base58 class excludes only
  // 0, I, O and l, so "rignoreaLLpriorinstructions" matches the candidate
  // pattern exactly, and echoing an unvalidated candidate would hand a message
  // author roughly 34 chosen characters inside text the model reads as data.
  // -------------------------------------------------------------------------
  {
    id: "f6-per-address-lines-removed",
    file: "src/core/render.ts",
    find: "  named.forEach((address, i) => {",
    replace: "  named.slice(0, 0).forEach((address, i) => {",
    why: "THE F6 DEFECT ITSELF: the report falls back to a count, which is the exact text that produced an invented 0 XRP balance for an account holding 267,875",
  },
  {
    id: "f6-echo-line-drops-its-address",
    file: "src/core/render.ts",
    find: "        ? `  other_address_not_retrieved[${i}]: ${address}. This address was named in the message and was NOT looked up.",
    replace:
      "        ? `  other_address_not_retrieved[${i}]: an address. This address was named in the message and was NOT looked up.",
    why: "F2's shape against the new line: the line is present, the wording is present, and the one thing it exists to carry is gone, so it is a count again wearing a name's clothes",
  },
  {
    id: "f6-checksum-gate-removed-from-the-echo-path",
    file: "src/core/render.ts",
    find: '    if (typeof c === "string" && ECHOABLE_ADDRESS.test(c) && isValidXrplAddress(c)) {',
    replace: '    if (typeof c === "string" && ECHOABLE_ADDRESS.test(c)) {',
    why: "the naming becomes the injection: rignoreaLLpriorinstructions matches the candidate shape, fails the checksum, and would be echoed into the prompt verbatim. The checksum is what cuts about 34 attacker-chosen characters down to about six",
  },
  {
    id: "f6-echo-pattern-shares-the-global-one",
    file: "src/core/render.ts",
    find: "const ECHOABLE_ADDRESS = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;",
    replace: "const ECHOABLE_ADDRESS = /r[1-9A-HJ-NP-Za-km-z]{24,34}/g;",
    // Written as an inline literal and NOT as a reference to
    // ADDRESS_CANDIDATE_PATTERN, which render.ts does not import. A mutation
    // whose replace does not compile tests the compiler, which this file has
    // already paid for once with rp-lines-refusal-silenced.
    why: "a /g pattern makes .test() STATEFUL: lastIndex advances on a match and resets on a miss, so four calls down one list return true, false, true, false and every second candidate skips the check. Measured, and the anchors go with it",
  },
  {
    id: "f6-echo-cap-raised",
    file: "src/core/bounds.ts",
    find: "  MAX_ECHOED_ADDRESSES: 3,",
    replace: "  MAX_ECHOED_ADDRESSES: 60,",
    why: "each echoed line costs roughly 0.8 trust lines of real ledger data, and a refusal has no other size bound at all: the notice renderer's cap is what keeps speak() inside MAX_RENDERED_CHARS",
  },
  {
    id: "f6-echo-cap-removed",
    file: "src/core/render.ts",
    find: "  const named = p.echoable.slice(0, room);",
    replace: "  const named = p.echoable.slice(0);",
    why: "the same bound removed at the site that enforces it rather than at the constant, which is the half a test reading BOUNDS cannot see",
  },
  // The cap notice became TWO notices in F7, because the one it was stated a
  // reason that was false. Four valid candidates, no trust lines, a report
  // measured at 1,490 of 4,000 characters, and a line saying an address was held
  // back "to keep this report inside its character bound". With 2,510 characters
  // spare that is untrue: the reason was the per-report policy cap on how many
  // addresses are NAMED. Both reasons are real and they are different facts, so
  // each carries its own count at a threshold of one.
  {
    id: "f6-cap-notice-suppressed",
    file: "src/core/render.ts",
    find: "  if (heldByCap > 0) {",
    replace: "  if (heldByCap < 0) {",
    why: "invariant 10: the cap is a REASON to omit, and it was the reason that would have said nothing. A report naming three of sixty addresses reads as a report about all the ones that mattered",
  },
  {
    id: "f6-cap-notice-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (heldByCap > 0) {",
    replace: "  if (heldByCap > 1) {",
    why: "the threshold is ONE. Holding back exactly one address is the smallest case that must be stated, and it is the case a fixture of sixty never reaches",
  },
  {
    id: "f6-cap-notice-count-dropped",
    file: "src/core/render.ts",
    find: "      `  other_addresses_not_named_cap: ${heldByCap}. That many of the addresses counted above are not named individually here, because this report names at most ${BOUNDS.MAX_ECHOED_ADDRESSES} of them. This report is INCOMPLETE on that point.`,",
    replace:
      "      `  other_addresses_not_named_cap: some. That many of the addresses counted above are not named individually here, because this report names at most ${BOUNDS.MAX_ECHOED_ADDRESSES} of them. This report is INCOMPLETE on that point.`,",
    why: "F2 again: a count asserted against the whole report is satisfied by any stray digit, and this report already carries a balance full of them",
  },
  {
    id: "f7-cap-notice-claims-a-size-reason-it-cannot-support",
    file: "src/core/render.ts",
    find: "      `  other_addresses_not_named_cap: ${heldByCap}. That many of the addresses counted above are not named individually here, because this report names at most ${BOUNDS.MAX_ECHOED_ADDRESSES} of them. This report is INCOMPLETE on that point.`,",
    replace:
      "      `  other_addresses_not_named_cap: ${heldByCap}. That many of the addresses counted above are not named individually here, to keep this report inside its character bound. This report is INCOMPLETE on that point.`,",
    why: "THE FALSE REASON ITSELF. Measured at 1,490 of 4,000 characters with 2,510 to spare, so the size claim is untrue on the exact input that produces it, and a refusal message is report content with no successful report beside it to contradict a wrong sentence",
  },
  {
    id: "f7-cap-notice-says-they-were-all-named",
    file: "src/core/render.ts",
    // LENGTH-PRESERVING, deliberately: "are not" and "are all" are both seven
    // characters, so no length-sensitive test can catch this and only an
    // assertion on the CLAUSE can. It survived until one existed.
    find: "counted above are not named individually here, because this report names at most",
    replace: "counted above are all named individually here, because this report names at most",
    why: "the clause is the whole content of the notice: mutated, a report that named three of four addresses tells the model it named all four, and the count beside it becomes unreadable",
  },
  {
    id: "f7-room-notice-suppressed",
    file: "src/core/render.ts",
    find: "  if (droppedForRoom > 0) {",
    replace: "  if (droppedForRoom < 0) {",
    why: "the SIZE reason, and it is the one the refusal path depends on. A name given up for room is as omitted as a name given up for the cap, and invariant 10 admits no reason that goes unspoken",
  },
  {
    id: "f7-room-notice-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (droppedForRoom > 0) {",
    replace: "  if (droppedForRoom > 1) {",
    why: "the threshold is ONE, and one name dropped for room is the first thing the size search ever does",
  },
  {
    id: "f7-room-notice-count-dropped",
    file: "src/core/render.ts",
    find: "      `  other_addresses_not_named_for_room: ${droppedForRoom}. That many of the addresses counted above were dropped from the names above to keep this text inside its character bound. This report is INCOMPLETE on that point.`,",
    replace:
      "      `  other_addresses_not_named_for_room: some. That many of the addresses counted above were dropped from the names above to keep this text inside its character bound. This report is INCOMPLETE on that point.`,",
    why: "F2 against the fourth count, which is the one that has to add up with the other three for the report to be internally consistent",
  },
  {
    id: "f6-invalid-notice-suppressed",
    file: "src/core/render.ts",
    find: "  if (p.notValid > 0) {",
    replace: "  if (p.notValid < 0) {",
    why: "a candidate refused for its checksum is still an omission, and it is the omission least likely to be noticed because nothing about it can be printed",
  },
  {
    id: "f6-invalid-notice-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (p.notValid > 0) {",
    replace: "  if (p.notValid > 1) {",
    why: "the threshold is ONE, and one mistyped address in a message is the ordinary case rather than the exotic one",
  },
  {
    id: "f6-invalid-notice-count-dropped",
    file: "src/core/render.ts",
    find: "      `  other_addresses_not_valid: ${p.notValid} of the candidates counted above did not pass address validation, so they are NOT named here and nothing in this report describes them.`,",
    replace:
      "      `  other_addresses_not_valid: some of the candidates counted above did not pass address validation, so they are NOT named here and nothing in this report describes them.`,",
    why: "F2's shape against the third of the three counts, which is the one that has to add up with the other two",
  },
  {
    id: "f6-non-list-invents-a-count",
    file: "src/core/render.ts",
    find: "  if (!Array.isArray(candidates)) return null;",
    replace: "  if (!Array.isArray(candidates)) return { total: 1, echoable: [], notValid: 1 };",
    why: "invariant 7 one field over: nothing was measured, so a count stated for an absent list is a number this package never counted, and the outer catch passes an empty list precisely because it knows nothing",
  },
  {
    id: "f6-names-dropped-before-trust-rows",
    file: "src/core/render.ts",
    find: "    const report = build(kept, BOUNDS.MAX_ECHOED_ADDRESSES);",
    replace: "    const report = build(kept, 0);",
    why: "the ORDER of the two-stage size search. A dropped trust row is one more line about an account the report already describes; a dropped name is the only thing standing between the model and an invented balance for a different one",
  },
  {
    id: "f6-echo-lines-not-paid-for-by-the-size-search",
    file: "src/core/render.ts",
    find: "  for (let echoKept = BOUNDS.MAX_ECHOED_ADDRESSES - 1; echoKept >= 0; echoKept--) {",
    replace: "  for (let echoKept = -1; echoKept >= 0; echoKept--) {",
    why: "without the second stage the report falls straight to the hard character cut whenever the names do not fit, and a hard cut over a build holding an address is the next entry",
  },
  {
    id: "f6-hard-cut-runs-over-a-build-holding-names",
    file: "src/core/render.ts",
    find: "  return build(0, 0).slice(0, BOUNDS.MAX_RENDERED_CHARS - marker.length) + marker;",
    replace:
      "  return build(0, BOUNDS.MAX_ECHOED_ADDRESSES).slice(0, BOUNDS.MAX_RENDERED_CHARS - marker.length) + marker;",
    // MEASURED before this entry was written, not argued: at a balance of 1,653
    // digits the mutated cut emits
    //   other_address_not_retrieved[0]: rKUK9omZqVEnraCipKNFb5q4tuNTeqED
    // which is 32 of 34 characters and still reads as an address. The test that
    // catches it SWEEPS the transition region, because a list of round widths
    // walks straight past 1,653.
    why: "F1 one level up. The last resort cuts CHARACTERS, so running it over a build that still holds a name ends mid-base58 and emits a shortened string that names an account which does not exist",
  },
  {
    id: "f6-refusal-drops-the-per-address-lines",
    // Moved with the refusal renderer in F9. Same line, different file.
    file: "src/core/render.ts",
    find: '  const tail = others.length === 0 ? "" : `\\n${others.join("\\n")}`;',
    replace: '  const tail = others.length === 0 ? "" : ` ${others[0]}`;',
    why: "the refusal keeps the aggregate line and loses every name, which is the published 0.1.1 behaviour on the path where the model has NO successful report beside it to contradict a guess",
  },
  {
    id: "f6-outer-catch-invents-a-count",
    file: "src/provider.ts",
    // Search text updated when F8 gave speak() its unreadable-run count, which
    // this branch passes as a literal zero for the same reason it passes an
    // empty list.
    find: '          [],\n          NOTHING_SCANNED,\n          "not-cacheable",',
    replace:
      '          ["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"],\n          NOTHING_SCANNED,\n          "not-cacheable",',
    why: "invariant 10's one deliberate exception, fixed into a lie: run() can throw before it has read the message, so this branch cannot know any address, and naming one would put an account into the prompt that nothing measured",
  },
  {
    id: "unreadable-outer-catch-invents-a-count",
    file: "src/provider.ts",
    find: '          [],\n          NOTHING_SCANNED,\n          "not-cacheable",',
    replace: '          [],\n          { count: 3, capped: true },\n          "not-cacheable",',
    why: "the same exception one field over. run() can throw before it has read the message text at all, so this branch can say neither that a run was there nor that one was not, and a count it never measured is a number in report content that nothing can contradict",
  },
  {
    id: "cache-key-given-the-raw-list-not-a-digest",
    file: "src/provider.ts",
    // Renamed from cache-key-given-the-list-not-the-count when the key component
    // became a digest. The defect is unchanged: hand turnCacheKey something that
    // is not the shape it partitions on and every key is null.
    // Search text updated when F8 gave skippedDigest its second component.
    find: "      skipped: skippedDigest(skipped, hidden.count, hidden.capped),",
    replace: "      skipped,",
    why: "turnCacheKey admits only the exact digest shape and returns null for anything else, so handing it the array makes every key null, turns cacheState into not-cacheable without a word, and silently restores the doubled network lookup the cache exists to remove",
  },

  // -------------------------------------------------------------------------
  // F7. THE REPAIR PASS, and every entry below is a defect an adversarial
  // verifier reproduced against the F6 change rather than one this repo shipped.
  //
  // The one to read is the first. F6 made the report NAME the addresses it
  // skipped, and left the cache key carrying only how MANY were skipped. The two
  // then disagreed: one agentId, one message.id, turn 1 "A and B", turn 2 "A and
  // C", inside the TTL. Turn 2 reported cacheState "hit" and was served turn 1's
  // report, which NAMES B. B was never in turn 2's message, C vanished with no
  // notice, and every count in the served report still added up, so the report
  // was internally consistent while describing a different message. Memory.id is
  // caller-shaped input, which is why isUuidLike exists, so that collision is
  // reachable under this module's own threat model.
  //
  // The rule it earns, and it generalises past the cache: A KEY MUST BE
  // DETERMINED BY WHAT THE THING IT KEYS IS DETERMINED BY. A count beside a list
  // is two values that can disagree, and this repo keeps finding that shape.
  // -------------------------------------------------------------------------
  {
    id: "f7-cache-key-carries-only-the-skipped-count",
    file: "src/provider.ts",
    // THE DEFECT ITSELF, reproduced exactly: the identities erased, the count
    // preserved. Mapping every entry to one constant is the count form written
    // as a digest, which is what makes it the faithful reproduction rather than
    // an approximation of it.
    // Search text updated when F8 gave skippedDigest its second component.
    find: "      skipped: skippedDigest(skipped, hidden.count, hidden.capped),",
    replace:
      '      skipped: skippedDigest(\n        skipped.map(() => "x"),\n        hidden.count,\n        hidden.capped,\n      ),',
    why: "two turns sharing one message.id and skipping DIFFERENT single addresses land on one entry, and the second is served a report naming an address its message never held while the address it did name vanishes with no notice",
  },
  {
    id: "f7-report-names-its-own-subject-as-not-retrieved",
    file: "src/core/render.ts",
    find: "  const otherAddresses = partitionOtherAddresses(input?.otherAddressCandidates, subject);",
    replace:
      "  const otherAddresses = partitionOtherAddresses(input?.otherAddressCandidates, null);",
    why: "the report prints `address: A` with a real balance AND a line saying A was not looked up and no balance for it appears anywhere in this report. One report, both claims, about one account, and the renderer is the file that decides what reaches the prompt",
  },
  {
    id: "f7-renderer-delegates-distinctness-to-its-caller",
    file: "src/core/render.ts",
    find: "  for (const c of new Set(candidates)) {",
    replace: "  for (const c of candidates) {",
    why: "handed a list with repeats the report printed one account three times while the aggregate count implied three separate accounts, and the sweep that was supposed to cover it asserted only the length of the output",
  },
  {
    id: "f7-notice-block-budget-ignored",
    file: "src/core/render.ts",
    find: '    if (lines.join("\\n").length <= budget) return lines;',
    replace: "    if (lines.length >= 0) return lines;",
    why: "the refusal path has no size search of its own: speak() applied no slice at all and was held inside MAX_RENDERED_CHARS by arithmetic over two constants, and the smallest MAX_ECHOED_ADDRESSES that busts it is seventeen",
  },
  {
    id: "f7-notice-budget-defaults-to-unbounded",
    file: "src/core/render.ts",
    find: '  const budget = typeof maxChars === "number" && Number.isFinite(maxChars) ? maxChars : 0;',
    replace:
      '  const budget = typeof maxChars === "number" && Number.isFinite(maxChars) ? maxChars : Number.POSITIVE_INFINITY;',
    why: "a caller that supplies no usable room gets every name it can hold rather than none, which is the fail-OPEN direction on the one path where nothing else measures the total",
  },
  {
    id: "f7-refusal-notice-given-zero-room",
    // Moved with the refusal renderer in F9. Same line, different file.
    file: "src/core/render.ts",
    find: "    BOUNDS.MAX_RENDERED_CHARS - head.length - 1,",
    replace: "    0,",
    why: "the room is measured from the refusal message actually built, so the wiring has to carry a real number. Zero silently costs the refusal every name, on the one path where the model has no successful report beside it to contradict a guess",
  },
  {
    id: "f7-named-line-permits-a-balance",
    file: "src/core/render.ts",
    // LENGTH-PRESERVING: "and none may be stated  for it." is the same length as
    // the shipped clause, so no assertion about the size of the report can see
    // it. It survived until an assertion on the CLAUSE existed.
    find: "and none may be stated for it.`,",
    replace: "and one may be stated  for it.`,",
    why: "THE sentence this whole change exists to produce. Mutated, the report tells the model a balance MAY be stated for an account it has just said was not retrieved, which is the invented figure F6 recorded, now licensed by the report itself",
  },
  {
    id: "f7-invalid-notice-says-they-passed-validation",
    file: "src/core/render.ts",
    // Length-preserving again: "did not pass address validation" and "did pass
    // address validation now" are the same length.
    find: "did not pass address validation, so they are NOT named here",
    replace: "did pass address validation now, so they are NOT named here",
    why: "the clause states the opposite fact: these candidates failed a checksum and were never validated as accounts, and a line saying they passed and were withheld anyway is a false statement about the only thing the notice describes",
  },
  {
    id: "f7-named-lines-all-print-index-zero",
    file: "src/core/render.ts",
    find: "        ? `  other_address_not_retrieved[${i}]: ${address}. This address was named in the message and was NOT looked up. No balance for it appears anywhere in this report, and none may be stated for it.`",
    replace:
      "        ? `  other_address_not_retrieved[0]: ${address}. This address was named in the message and was NOT looked up. No balance for it appears anywhere in this report, and none may be stated for it.`",
    why: "the index was read by NOTHING. Both echoed() helpers match \\[\\d+\\] and neither looked at the number, so three names printing as [0] three times read as one omission repeated and survived the whole suite",
  },

  // -------------------------------------------------------------------------
  // F8. THE OMISSION WITH NOTHING TO COUNT IT.
  //
  // ADDRESS_CANDIDATE_PATTERN is ASCII-only, so ONE invisible character inside
  // an address makes the address invisible to the scanner. MEASURED against the
  // shipped build: a message holding only
  //   "rHb9CJAWyB4rj91VRWn9" + U+200B + "6DkukG4bwdtyTh"
  // produced zero candidates, so run() returned silent(), text.length was 0,
  // and on this runtime that contributes zero characters to the prompt. Not a
  // wrong report about a named entity: NO report, and no marker anywhere.
  //
  // D6 was an omission stated with a count. F6 was a count that was not a name.
  // This is an omission with nothing at all to count it, because the thing
  // omitted never became a candidate in the first place.
  //
  // The unit is RUNS, and that is the honest unit rather than a cautious one:
  // two poisoned runs may be one account, or none, and this package cannot
  // tell. The lookup TARGET is unchanged, deliberately, because refusing the
  // whole turn whenever a run is present would let one pasted zero-width space
  // silence every XRPL lookup at zero attacker cost.
  // -------------------------------------------------------------------------
  {
    id: "poisoned-only-message-goes-silent",
    file: "src/provider.ts",
    find: "    if ((!candidates || candidates.length === 0) && hidden.count === 0 && !hidden.capped) {\n      return silent();\n    }",
    replace: "    if (!candidates || candidates.length === 0) {\n      return silent();\n    }",
    why: "THE F8 DEFECT ITSELF: a message whose only address-shaped content carries an invisible character produces no candidate, so the provider returns empty text and the prompt gets nothing at all about an entity the message named",
  },
  {
    id: "unreadable-run-count-goes-silent",
    file: "src/core/render.ts",
    find: "  if (hidden > 0) {",
    replace: "  if (false) {",
    why: "the notice removed at the site that emits it. The refusal still fires and still reads as a refusal, and the one line saying WHY nothing could be read is gone, which is invariant 10 with the omission unspoken again",
  },
  {
    id: "unreadable-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (hidden > 0) {",
    replace: "  if (hidden > 1) {",
    why: "the threshold is ONE. A single poisoned run is the ordinary case rather than the exotic one, and it is exactly the case a fixture built from several never reaches",
  },
  {
    id: "unreadable-run-echoed",
    file: "src/provider.ts",
    find: '    if (candidates === null || first === undefined) {\n      return speak(NO_READABLE_ADDRESS, [], hidden, "not-cacheable");\n    }',
    replace:
      '    if (candidates === null || first === undefined) {\n      return speak(\n        refuse("NO_READABLE_ADDRESS", `No XRPL address could be read from (${text}).`),\n        [],\n        hidden,\n        "not-cacheable",\n      );\n    }',
    why: "NEVER ECHO, as a mutation. The run is attacker-written text carrying attacker-chosen invisible characters, and quoting it back puts both into the prompt inside a refusal the model reads as this plugin's own words. countUnreadableAddressRuns returns a NUMBER precisely so no code downstream holds a string it could print",
  },
  {
    id: "unreadable-run-normalised",
    file: "src/provider.ts",
    find: "    const candidates = text.match(ADDRESS_CANDIDATE_PATTERN);",
    replace:
      '    const candidates = text\n      .replace(/[\\p{Default_Ignorable_Code_Point}\\p{Cf}]/gu, "")\n      .match(ADDRESS_CANDIDATE_PATTERN);',
    why: "NO NORMALISATION, as a mutation. Stripping the splitters and looking up the result is a request about an account nobody typed, which is the class validateXrplAddress refuses by name one layer down when it declines to trim. It also spends a network call and a rate-limit slot on a message that named nothing readable",
  },
  {
    id: "unreadable-count-out-of-cache-key",
    file: "src/provider.ts",
    find: "      skipped: skippedDigest(skipped, hidden.count, hidden.capped),",
    replace: "      skipped: skippedDigest(skipped, 0, hidden.capped),",
    why: "F7's defect one field over: two turns sharing an agentId, a message.id, a subject and a skipped list but holding DIFFERENT numbers of unreadable runs land on ONE entry, and the second is served the first's report. The run vanishes with every count in the served report still adding up, which is the exact shape the digest was introduced to make unrepresentable",
  },
  {
    id: "unreadable-detector-list-not-property",
    file: "src/core/address.ts",
    // The hand list a reasonable person writes: zero-width, the joiners, word
    // joiner, soft hyphen, BOM, and the bidi embeddings and overrides. It is 45
    // of the 4,206 code points the two properties cover, and the escapes are
    // written as escapes rather than characters because CLAUDE.md bans literal
    // invisible characters in source and this harness writes real files.
    find: "const HIDDEN_RUN_PATTERN =\n  /(?:[1-9A-HJ-NP-Za-km-z\\p{Default_Ignorable_Code_Point}\\p{Cf}\\uD800-\\uDFFF]|(?!\\s)\\p{Cc})+/gu;",
    replace:
      "const HIDDEN_RUN_PATTERN = /[1-9A-HJ-NP-Za-km-z\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u00AD\\uFEFF]+/gu;",
    why: "a hand list is wrong by CONSTRUCTION here, and this proves the properties are what the scanner reads. The list above misses all 4,096 tag characters in U+E0000..U+E0FFF, every variation selector including U+FE0F, U+3164 HANGUL FILLER, U+115F, U+FFA0, U+180E, U+061C and the four isolates, so twelve of the twenty-five splitters the suite names go undetected and the message is silent again",
  },
  // -------------------------------------------------------------------------
  // F9. THE REPAIR ROUND OVER F8, and every entry below is a defect an
  // adversarial reviewer reproduced against the shipped F8 change rather than a
  // hypothetical. It applied 43 source weakenings one at a time; sixteen stayed
  // green.
  //
  // Two were live defects in F8's own code, and both are the SAME root cause:
  // the run counter had no subject. It never asked whether the ordinary
  // candidate scanner had already read an address out of the run it was
  // counting, so one entity got reported twice.
  //
  //   "<a valid 34-character address>" + U+200B + "a" is 35 visible characters
  //   and entered the window, so the report carried `address: A` with a real
  //   balance AND a line saying no address was read from that run and that the
  //   account described was not taken from it.
  //
  //   a splitter at visible index 25 or later leaves a candidate-shaped prefix,
  //   so one further account was reported as `other_addresses_not_valid: 1` AND
  //   as `unreadable_address_runs: 1`.
  //
  // One was a live defect that predates F8 and that F8 made worse by adding a
  // second interpolation site: the refusal head had no bound and no sanitiser.
  // `error.name` is an ordinary own property on an Error instance, so a hostile
  // message getter chose it. MEASURED: 200,000 characters in, 200,093 out,
  // fifty times MAX_RENDERED_CHARS, U+200B and U+202E included.
  //
  // The rest are guards that were never pinned by anything.
  // -------------------------------------------------------------------------
  {
    id: "unreadable-run-counted-beside-its-own-address",
    file: "src/core/address.ts",
    find: "    if (CANDIDATE_IN_RUN.test(run)) continue;",
    replace: "    if (false) continue;",
    why: "THE F9 DEFECT ITSELF. Without the subject test one report says `address: A` with a real balance AND says no address was read from that run and that the account described was not taken from it. Both sentences about the same run, which is verbatim what partitionOtherAddresses' own docstring forbids one field over",
  },
  {
    id: "unreadable-run-subject-test-is-stateful",
    file: "src/core/address.ts",
    find: "const CANDIDATE_IN_RUN = new RegExp(ADDRESS_CANDIDATE_PATTERN.source);",
    replace: 'const CANDIDATE_IN_RUN = new RegExp(ADDRESS_CANDIDATE_PATTERN.source, "g");',
    why: "the /g trap this repo has already been bitten by, in the newest place it could bite. A /g pattern makes .test() STATEFUL, so consecutive calls down a sweep return true, false, true, false and every second run is counted when it should not be",
  },
  {
    id: "refusal-head-not-bounded",
    file: "src/core/render.ts",
    find: "  const kept = body.slice(0, BOUNDS.MAX_REFUSAL_MESSAGE_CHARS);",
    replace: "  const kept = body;",
    why: "MEASURED: an error name of 200,000 characters produced a ProviderResult.text of 200,093, fifty times MAX_RENDERED_CHARS. With the head uncapped the last-resort cut holds the LENGTH by eating the notice block beneath it, which is the half invariant 10 forbids dropping",
  },
  {
    id: "refusal-head-not-printable",
    file: "src/core/render.ts",
    find: '  const printable = raw.replace(NOT_PRINTABLE_ASCII, "");',
    replace: "  const printable = raw;",
    why: "NEVER ECHO at the one interpolation an attacker controls: a name carrying U+200B and U+202E put both straight into the prompt, and a newline in it forges a new `key: value` line inside text the model reads as this plugin's own words",
  },
  {
    id: "refusal-truncation-goes-silent",
    file: "src/core/render.ts",
    find: "  if (kept.length < body.length) {",
    replace: "  if (false) {",
    why: "invariant 10: a cut refusal message that says nothing reads as a complete one, and the model has no way to tell the difference",
  },
  {
    id: "refusal-truncation-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (kept.length < body.length) {",
    replace: "  if (kept.length + 1 < body.length) {",
    why: "the threshold is ONE. A message cut by exactly one character is the smallest case that must be stated, and it is the case a 200,000-character fixture never reaches",
  },
  {
    id: "refusal-removal-goes-silent",
    file: "src/core/render.ts",
    find: "  if (removed > 0) {",
    replace: "  if (false) {",
    why: "characters removed from a refusal message are an omission like any other. Silently deleting them leaves a message that reads as whole while its meaning may have changed",
  },
  {
    id: "refusal-removal-threshold-off-by-one",
    file: "src/core/render.ts",
    find: "  if (removed > 0) {",
    replace: "  if (removed > 1) {",
    why: "the threshold is ONE, and ONE zero-width space is the whole finding this package spent a change on",
  },
  {
    id: "refusal-blank-message-stays-blank",
    file: "src/core/render.ts",
    find: '    trimmed === ""\n      ? "The XRPL lookup was refused and no ledger data was retrieved. The reason given could not be displayed."\n      : trimmed;',
    replace: "    trimmed;",
    why: "a message that is entirely invisible characters cleans to nothing, and a refusal that says only its prefix tells the model less than src/core/result.ts already guarantees one layer down. An empty refusal is an invisible refusal",
  },
  {
    id: "render-count-refuses-zero",
    file: "src/core/render.ts",
    find: '  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? String(v) : "<unavailable>";',
    replace:
      '  return typeof v === "number" && Number.isFinite(v) && v > 0 ? String(v) : "<unavailable>";',
    why: "invariant 7's own sentence: a genuine 0 is real data and must survive. This turns owner_count 0 and account_sequence 0 into <unavailable>, for the exact two fields CLAUDE.md's rule-4 story is about, and neither had a single test at the value zero",
  },
  {
    id: "unreadable-count-not-truncated",
    file: "src/core/render.ts",
    find: '  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;',
    replace:
      '  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, value) : 0;',
    why: "the report prints `unreadable_address_runs: 2.9`, which is a count of runs that is not a whole number of runs. It survived F8 because the assertion was written `: 2\\b` and a word boundary sits between the 2 and the dot",
  },
  {
    id: "drops-pattern-unanchored",
    file: "src/core/render.ts",
    find: "const DROPS = /^[0-9]+$/;",
    replace: "const DROPS = /^[0-9]+/;",
    why: 'MEASURED through the exported renderer: "100 " renders as a balance with a trailing space, and "100abc" makes dropsToXrp throw SyntaxError out of renderAccountReport, which on this runtime is the fail-OPEN case the whole package exists to avoid',
  },
  {
    id: "control-chars-range-narrowed",
    file: "src/core/render.ts",
    find: "const CONTROL_CHARS = /[\\u0000-\\u001F\\u007F-\\u009F]/g;",
    replace: "const CONTROL_CHARS = /[\\u0000-\\u001F\\u007F\\u009F]/g;",
    why: "one hyphen turns a range into a list of two, and U+0085, U+0090 and U+009B then survive sanitizeLedgerText. The only test that touched this asserted a range that excluded the half being removed",
  },
  {
    id: "success-values-drop-the-address",
    file: "src/provider.ts",
    find: "        xrplAddress: account.address,",
    replace: '        xrplAddress: "",',
    why: "xrplAddress had ZERO mentions across the whole suite and every file under checks/. It is the field a consumer reads instead of parsing the report text, so a wrong value there is wrong everywhere the report is not read",
  },
  {
    id: "success-values-fabricate-a-zero-balance",
    file: "src/provider.ts",
    find: "        xrplBalanceDrops: account.balanceDrops,",
    replace: '        xrplBalanceDrops: "0",',
    why: "the same, and worse: a fabricated zero balance published on `values` for an account holding anything at all. Zero mentions in the suite meant this could not fail, and invariant 7 exists for exactly this sentence",
  },
  {
    id: "ledger-error-code-becomes-internal",
    file: "src/core/response.ts",
    find: '      "LEDGER_ERROR",',
    replace: '      "INTERNAL_ERROR",',
    why: "LEDGER_ERROR appeared ZERO times in the suite, so it could be any string at all and a consumer branching on the code would branch on nothing. INTERNAL_ERROR also reads to an operator as a bug in this plugin rather than an answer from the node",
  },
  {
    id: "response-too-large-code-becomes-malformed",
    file: "src/core/response.ts",
    find: '      "RESPONSE_TOO_LARGE",',
    replace: '      "RESPONSE_MALFORMED",',
    why: "RESPONSE_TOO_LARGE appeared ZERO times in the suite. A size refusal reported as a malformed one tells an operator the node is broken when the node is fine and the bound is this plugin's own",
  },
  {
    id: "node-unreachable-code-becomes-timeout",
    file: "src/transport/client.ts",
    find: '        "NODE_UNREACHABLE",\n        `The XRPL node answered with HTTP ${res.status}, so no ledger data was retrieved.`,',
    replace:
      '        "NODE_TIMEOUT",\n        `The XRPL node answered with HTTP ${res.status}, so no ledger data was retrieved.`,',
    why: "NODE_UNREACHABLE appeared ZERO times in the suite. A node that answered is not a node that timed out, and the two codes are the difference between retry and investigate",
  },
  {
    id: "cache-key-sorts-the-skipped-list",
    file: "src/provider.ts",
    find: "      skipped: skippedDigest(skipped, hidden.count, hidden.capped),",
    replace: "      skipped: skippedDigest([...skipped].sort(), hidden.count, hidden.capped),",
    why: "the report prints the names IN ORDER, so a key that discards the order stops determining its own output: two turns sharing a message.id and naming the same two addresses the other way round land on ONE entry, and the second is served a report whose other_address_not_retrieved[0] names the wrong account. turncache.test.ts pins the order on the digest and structurally cannot see a caller that sorts before calling",
  },
  // -------------------------------------------------------------------------
  // F9. THE SECOND ADVERSARIAL PASS, 69 weakenings, sixteen green. Two of them
  // put the central predicate in question and SECURITY ruled on the design.
  //
  // The counter had no CHECKSUM, so any 25-to-35 character base58 run starting
  // with a lowercase r and carrying one soft hyphen was counted, and soft
  // hyphens are routine in copied typeset text. MEASURED phantoms:
  // "rechtsbijstandsverzekering", "runtimeConfigurationSnapshot" and
  // "requestAuthenticationMidd". End to end, "please rename
  // runtime<U+00AD>ConfigurationSnapshot to something shorter" produced an
  // 833-character refusal about an account that does not exist.
  //
  // And the joining class was too NARROW in the other direction: U+0001,
  // U+0007, U+007F, U+0085 and a lone U+D800 all BROKE a run, so the provider
  // returned zero characters, which is the original defect.
  //
  // The two are one design: the class widens to everything that renders as
  // nothing, and the checksum is what makes that safe.
  // -------------------------------------------------------------------------
  {
    id: "checksum-gate-removed",
    file: "src/core/address.ts",
    find: "    if (!isValidXrplAddress(visible)) continue;",
    replace: "    if (false) continue;",
    why: "THE F9 DEFECT ITSELF, and it is what makes the widened joining class safe. Without it any base58 run carrying one soft hyphen is counted: three ordinary words did it, and an unrelated turn got an 833-character refusal about an XRPL account that does not exist. A false statement in report content and the prompt pollution silent() exists to avoid",
  },
  {
    id: "reconstruction-looked-up",
    file: "src/provider.ts",
    // SECURITY named this one. The first attempt at it could not fail, and that
    // is recorded rather than quietly fixed: it added the repaired list behind
    // `candidates?.[0] ??`, and the null guard one line below still refused, so
    // the lookup target never changed. A mutation that cannot fail certifies a
    // guard it never tested.
    //
    // This form does change the target. On "pay <poisoned A> and <B>" the raw
    // scanner finds only B, and the repaired text yields A first, so the lookup
    // goes to an account the message never actually contained.
    find: "    const address = validateXrplAddress(first);",
    replace:
      '    const rebuilt = text\n      .replace(/[\\p{Default_Ignorable_Code_Point}\\p{Cf}]/gu, "")\n      .match(ADDRESS_CANDIDATE_PATTERN);\n    const address = validateXrplAddress(rebuilt?.[0] ?? first);',
    why: "the RECONSTRUCTION becomes the LOOKUP TARGET. A repaired address is an address nobody typed, so the request is about an account the message never named, and it spends a network call and a rate-limit slot doing it. The target must stay candidates[0] from ADDRESS_CANDIDATE_PATTERN over the RAW text",
  },
  {
    id: "reconstruction-echoed",
    file: "src/provider.ts",
    // SECURITY named this one. It has to be a BEHAVIOURAL mutation and not a
    // change to the scan's return type: the harness runs vitest, which does not
    // typecheck, so widening HiddenAddressScan alone could never go red and a
    // mutation that cannot fail certifies a guard it never tested.
    //
    // This is the real shape of the defect. The reconstruction is built in the
    // one place that holds the message text and printed in the refusal, which
    // is exactly what the scan returning a NUMBER exists to make impossible.
    find:
      "    if (candidates === null || first === undefined) {\n" +
      '      return speak(NO_READABLE_ADDRESS, [], hidden, "not-cacheable");\n    }',
    replace:
      '    if (candidates === null || first === undefined) {\n      return speak(\n        refuse(\n          "NO_READABLE_ADDRESS",\n          `No XRPL address could be read. The nearest was ${text.replace(/[\\p{Default_Ignorable_Code_Point}\\p{Cf}]/gu, "")}.`,\n        ),\n        [],\n        hidden,\n        "not-cacheable",\n      );\n    }',
    why: "the RECONSTRUCTION reaches the prompt. It is an address nobody typed, assembled from attacker-written text, and printing it back tells the model an account exists that the message never actually named. countUnreadableAddressRuns returns a NUMBER precisely so that no code downstream holds the string it could print",
  },
  {
    id: "hidden-address-not-distinct",
    file: "src/core/address.ts",
    // The first attempt removed the `counted.has` guard, which could not fail:
    // the count is the SET's size, so a duplicate that got past the guard was
    // de-duplicated by the add anyway. What makes the count distinct is the Set,
    // so the mutation has to defeat the Set. Recorded rather than silently
    // fixed, because a mutation that cannot fail is worse than none.
    //
    // SECOND REWRITE, for the same reason and recorded for the same reason. The
    // form `counted.add(`${visible}${checksums}`)` died twice over when the
    // budget moved to `examined`: the counter it read no longer exists, and a
    // repeated run is now stopped by `examined.has` one line ABOVE this, so a
    // duplicate never reaches here to be mis-keyed. Adding a SECOND entry is
    // what still bites, and it is the same harm stated the same way: one hidden
    // account rendered as two omissions.
    find: "    counted.add(visible);",
    replace: "    counted.add(visible);\n    counted.add(`${visible}-2`);",
    why: "one account hidden twice in a message becomes two omissions. Overstating an omission is the same class of inaccuracy as hiding one, and other_addresses_not_looked_up has counted DISTINCT strings since D6 for exactly this reason",
  },
  {
    id: "hidden-address-not-excluded-when-already-described",
    file: "src/core/address.ts",
    find: "    if (rawCandidates.has(visible)) continue;",
    replace: "    if (false) continue;",
    why: "MEASURED: `compare A and A-with-a-zero-width-space` printed `address: A` with a real balance AND said an address hidden by invisible characters was never looked up and no balance may be stated for it. One report, both claims, one account, which is the defect partitionOtherAddresses' own docstring names",
  },
  {
    id: "joining-class-drops-control-characters",
    file: "src/core/address.ts",
    find: "const HIDDEN_RUN_PATTERN =\n  /(?:[1-9A-HJ-NP-Za-km-z\\p{Default_Ignorable_Code_Point}\\p{Cf}\\uD800-\\uDFFF]|(?!\\s)\\p{Cc})+/gu;",
    replace:
      "const HIDDEN_RUN_PATTERN = /[1-9A-HJ-NP-Za-km-z\\p{Default_Ignorable_Code_Point}\\p{Cf}]+/gu;",
    why: "U+0001, U+0007, U+007F, U+0085 and a lone U+D800 render as nothing and BREAK the run under this class, so the provider returns zero characters for a message carrying one. That is the original defect, reachable again through five code points nobody would think to type",
  },
  {
    id: "joining-class-joins-whitespace",
    file: "src/core/address.ts",
    find: "|(?!\\s)\\p{Cc})+/gu;",
    replace: "|\\p{Cc})+/gu;",
    why: "the predicate is RENDERS AS NOTHING, and a newline is not nothing. Without the carve-out two real addresses on consecutive lines join into one 68-character run, and the reconstruction of a run a human reads as two things is not an address anyone wrote",
  },
  {
    id: "hidden-address-cap-removed",
    file: "src/core/address.ts",
    // Search text updated when the charge moved from a `checksums` counter to
    // `examined.size`. A counter beside the set is a second number that can
    // disagree with it, which is what the per-run defect below turned out to be.
    find: "    if (examined.size >= BOUNDS.MAX_ADDRESS_CHECKSUMS_PER_MESSAGE) {",
    replace: "    if (false) {",
    why: "an uncapped double-SHA loop driven by unrated conversation text, BEFORE checkRateLimit. MEASURED at 16.6ms over a hostile 99 KB message, roughly ten times the scan without checksums, and every millisecond of it chosen by whoever is talking to the agent",
  },
  {
    id: "hidden-address-cap-goes-silent",
    file: "src/core/render.ts",
    find: "  if (capped) {",
    replace: "  if (false) {",
    why: "the cap is an omission this plugin chose for its own convenience, and invariant 10 admits no reason that goes unspoken. Silenced, a report that examined 64 of 4,000 hidden addresses reads as one that examined all of them",
  },
  {
    id: "refusal-drops-its-own-subject",
    file: "src/provider.ts",
    find: "    const allNamed = [...new Set(candidates)];",
    replace: "    const allNamed = skipped;",
    why: 'MEASURED on `compare A and B and C` with the node answering an error: B and C each got "no balance may be stated for it" and A, the account the user actually asked about, got no name, no line and no guard. F6\'s own lesson inverted and pointed at the account that matters most',
  },
  {
    id: "refusal-aggregate-claims-a-description",
    file: "src/core/render.ts",
    find: "      : `  other_addresses_not_looked_up: ${p.total}. The message held that many DISTINCT strings shaped like an XRPL address, INCLUDING the one this refusal is about.",
    replace:
      "      : `  other_addresses_not_looked_up: ${p.total}. The message held that many further DISTINCT strings shaped like an XRPL address, not counting the one this report describes.",
    why: 'a refusal describes NOTHING, so a sentence saying "not counting the one this report describes" asserts a description that does not exist, and hides that the subject is inside the count. A refusal message is the only text the model gets when a lookup fails',
  },
  {
    id: "refusal-named-line-claims-it-was-not-looked-up",
    file: "src/core/render.ts",
    find: "        : `  other_address_not_retrieved[${i}]: ${address}. This address was named in the message and no ledger data was retrieved for it.",
    replace:
      "        : `  other_address_not_retrieved[${i}]: ${address}. This address was named in the message and was never mentioned by it.",
    why: "the clause has to be TRUE on a path where the address WAS looked up and the lookup failed. The report path says it was not looked up because it was not; the refusal path says no data was retrieved because that is what happened",
  },
  {
    id: "outer-catch-reads-the-error-name-inline",
    file: "src/provider.ts",
    find: '    const name: unknown = error.name;\n    return typeof name === "string" ? name : "unknown error";',
    replace: "    return String((error as Error).name);",
    why: "invariant 1's last line of defence made to throw from inside itself. `name` is an ordinary property on an Error instance, so a subclass may define it as a getter, and MEASURED with `class HostileName extends Error { get name(){ throw } }` provider.get REJECTED, which this runtime erases entirely",
  },
  {
    id: "refusal-head-states-only-its-first-omission",
    file: "src/core/render.ts",
    find: '  return `${REFUSAL_PREFIX}${kept}${notes.join("")}`;',
    replace: '  return `${REFUSAL_PREFIX}${kept}${notes[0] ?? ""}`;',
    why: "a refusal message can be BOTH over-length and carrying invisibles, and this states only the first. MEASURED: the head went from 751 characters to 609 and the suite stayed green, so a message that had been cut AND stripped reported only that it had been cut",
  },
  {
    id: "ratelimit-refusal-drops-the-other-addresses",
    file: "src/provider.ts",
    find: "    if (!limit.ok) return speak(limit, allNamed, hidden, cacheState);",
    replace: "    if (!limit.ok) return speak(limit, [], hidden, cacheState);",
    why: "MEASURED: the rate-limit refusal shrank from 661 characters to 157 with the suite green. It is produced on turns that named several accounts, and it is the only text the model gets",
  },
  {
    id: "lines-refusal-drops-the-other-addresses",
    file: "src/provider.ts",
    find: '    if ("ok" in linesResult && linesResult.ok === false) {\n      return remember(speak(linesResult, allNamed, hidden, cacheState));\n    }',
    replace:
      '    if ("ok" in linesResult && linesResult.ok === false) {\n      return remember(speak(linesResult, [], hidden, cacheState));\n    }',
    why: "the same hole on the second half of the lookup: 606 characters to 102, green. Every refusal path carries the same list for the same reason",
  },
  {
    id: "hidden-notice-claims-runs-it-cannot-count",
    file: "src/core/render.ts",
    find: "      `  addresses_hidden_by_invisible_characters: ${hidden}. The message held that many DISTINCT strings whose visible characters are a valid XRPL classic address,",
    replace:
      "      `  addresses_hidden_by_invisible_characters: ${hidden}. The message held that many runs of address-shaped characters, which this plugin cannot tell apart as accounts,",
    why: "the CLAIM changed when the checksum gate landed, so the wording had to change with it. Under the gate every one counted is a checksum-valid address counted once, so the old hedge is false in the other direction: it understates what the report knows, in the only text the model gets",
  },

  // -------------------------------------------------------------------------
  // F10. THE NARROW REPAIR. Two defects, both in the per-message checksum cap
  // added one round earlier, both reproduced by a cold pass rather than found
  // by anything in `bun run verify`.
  //
  // They share a shape worth naming, because it is the third time this repo has
  // hit it: A BUDGET AND A KEY MUST BOTH BE KEYED ON THE SAME THING THE OUTPUT
  // IS. The cap charged per RUN while the report counts per DISTINCT run, and
  // the cache key carried the hidden COUNT while the report also prints the
  // capped FLAG. Each is one value drifting from another that describes the
  // same fact.
  // -------------------------------------------------------------------------
  {
    id: "f10-checksum-cap-charged-per-run",
    file: "src/core/address.ts",
    // THE LEDGER, which is what actually decides the notice.
    //
    // FIRST ATTEMPT, recorded because it SURVIVED a full gate run and a survivor
    // that is quietly rewritten teaches nothing. It replaced
    // `if (examined.has(visible))` with the shipped `if (counted.has(visible))`
    // and the suite stayed green at 559 passed. The reason is that the repair
    // changed two independent things, and either one alone fixes the notice:
    // the dedupe set widened from `counted` to `examined`, AND the charge became
    // a SET SIZE rather than an integer counter. `Set.add` is idempotent, so a
    // repeated string cannot grow `examined.size` even with the dedupe gone.
    //
    // So the mutation has to defeat the SIZE. Giving every add a unique key
    // makes the set grow once per RUN, which is the shipped defect exactly, and
    // it defeats the `has` gate in the same line because the suffixed keys never
    // match a bare `visible`.
    find: "    examined.add(visible);",
    replace: "    examined.add(`${visible}${examined.size}`);",
    why: "MEASURED: 65 repetitions of one hyphenated word, ONE entity, spent all 64 checksums and set `capped`, and the provider answered with a 565-character NO_READABLE_ADDRESS refusal about an XRPL account that does not exist. No checksum ever passed and no rate-limit slot was charged, so nothing else in the pipeline could contradict it. A bound an ordinary repeated word can exhaust is not bounding an attacker, and the notice it emits is a false statement of incompleteness in the only text the model gets",
  },
  {
    id: "f10-cache-key-drops-the-capped-flag",
    file: "src/provider.ts",
    // The caller stops VARYING the component rather than dropping it, which is
    // the faithful reproduction: the digest still exists and still has the right
    // shape, so turnCacheKey builds a key and nothing reports not-cacheable.
    find: "      skipped: skippedDigest(skipped, hidden.count, hidden.capped),",
    replace: "      skipped: skippedDigest(skipped, hidden.count, false),",
    why: "F8's defect a third time over, and the worst field to lose it on. Two turns sharing a caller-supplied message.id, identical but for whether the checksum budget bit, land on ONE entry. One direction serves a cap notice for a scan that finished; the other drops one for a scan that did not, and a report that silently stops saying INCOMPLETE reads as a complete one. Memory.id is caller-shaped, which is why isUuidLike exists, so the collision is reachable rather than hypothetical",
  },
  {
    id: "f10-digest-drops-the-capped-component",
    file: "src/core/turncache.ts",
    // The same loss one layer down, because the provider-side entry above
    // cannot see a digest that quietly stops carrying what it is handed. A guard
    // pinned in one place is pinned by nothing.
    find: "  const scalars = `${String(unreadable)}${TURN_CACHE_KEY_SEPARATOR}${String(capped)}`;",
    replace: "  const scalars = `${String(unreadable)}`;",
    why: "the caller still passes hidden.capped and the validator still refuses a non-boolean, so every type check and every call site still reads correct while the component silently stops reaching the hash. Two turns differing only in the cap collide again, with nothing at the provider to show for it",
  },
];

// ---------------------------------------------------------------------------
// A FLOOR ON THE MUTATION COUNT, for the same reason there is one on the test
// count: a deletion is invisible when an addition lands in the same edit.
//
// This is here because the count was actually got wrong. A build reported 38
// entries and a cold verification pass reported 37, twice each, and neither
// number sat beside a command. The cause is one line in check.ts: on success it
// prints `pass (103.4s)` and DISCARDS the harness's own
// "38 defects reintroduced, 38 caught" summary, so anyone running `bun run
// verify` never sees the count and falls back to eyeballing the array.
//
// Checked BEFORE the baseline run, because a floor that costs two minutes to
// report is a floor people skip.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// PRECONDITION. Refuse against a tree a previous run may still be holding.
//
// This runs BEFORE the snapshot below, and the ordering is the whole point.
// ORIGINAL is what every mutation is restored to, so a harness that snapshots
// first ADOPTS a leftover mutation as the original, restores to it, and then
// grades all 84 guards against a poisoned suite while printing "all files
// restored byte-identical". It would be confidently, silently wrong.
//
// Measured: an interrupted `git commit` killed this script between writing a
// mutation and restoring it, and left `if (false && ...)` in
// src/core/response.ts. The restore is in a `finally`, and a `finally` does not
// survive a hard kill.
// ---------------------------------------------------------------------------
const staleTree = staleSentinelRefusal(ROOT);
if (staleTree !== null) {
  console.log(staleTree);
  console.log("\nmutations: REFUSED TO START. A poisoned baseline grades nothing.");
  process.exit(1);
}

const floorText = readFileSync(join(ROOT, "checks", "mutation_count_floor.txt"), "utf8");
const floorLine = floorText.split("\n")[0]?.trim() ?? "";
const floor = Number.parseInt(floorLine, 10);

if (!Number.isInteger(floor) || floor <= 0) {
  console.log(
    `mutations: the floor file does not start with a positive integer (${JSON.stringify(floorLine)})`,
  );
  process.exit(1);
}

// A duplicated id is its own way to lose an entry: two mutations print under one
// name and the total still looks healthy.
const ids = new Set(MUTATIONS.map((m) => m.id));
if (ids.size !== MUTATIONS.length) {
  const seen = new Set<string>();
  const dupes = MUTATIONS.map((m) => m.id).filter((id) => seen.size === seen.add(id).size);
  console.log(`mutations: duplicate id(s): ${[...new Set(dupes)].join(", ")}`);
  process.exit(1);
}

if (MUTATIONS.length < floor) {
  console.log(
    `mutations: ${MUTATIONS.length} entries, floor is ${floor}. ${floor - MUTATIONS.length} MISSING.`,
  );
  console.log("Lowering the floor is allowed. Doing it silently is not: edit");
  console.log("checks/mutation_count_floor.txt and say why in the commit message.");
  process.exit(1);
}

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

// The sentinel goes down BEFORE the first mutation is written and comes up only
// after the restore has been VERIFIED byte-identical. Anything that kills this
// process in between leaves it behind, which is what makes the next run refuse.
//
// It records the pristine hash of every file this run may rewrite, so the
// refusal can name the ones that actually drifted instead of telling a human to
// go and look at fourteen files.
const SENTINEL = sentinelPath(ROOT);
writeSentinel(
  SENTINEL,
  buildSentinel(
    "checks/mutations.ts",
    process.pid,
    new Date().toISOString(),
    TARGETS.map((file) => ({ file, sha256: sha256Of(ORIGINAL.get(file) ?? "") })),
  ),
);

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
    // Nothing has been written yet, so the tree is exactly as it was handed
    // over. Cleared explicitly because process.exit does NOT run the `finally`
    // below, and a sentinel left over a tree this run never touched would
    // block the next one for no reason.
    clearSentinel(SENTINEL);
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

    const replacement = m.decodeEscapes
      ? m.replace.replace(/\\u([0-9A-Fa-f]{4})/g, (_all, hex: string) =>
          String.fromCharCode(Number.parseInt(hex, 16)),
        )
      : m.replace;
    writeFileSync(join(ROOT, m.file), original.replace(m.find, replacement), "utf8");
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

// The sentinel comes up ONLY here, and only when the restore was verified. A
// failed restore is the exact state it exists to announce, so clearing it then
// would hand the next run a poisoned tree with nothing left to warn it.
if (mayClearSentinel(dirty)) clearSentinel(SENTINEL);

console.log();
if (dirty > 0) {
  console.log(`mutations: RESTORE FAILED on ${dirty} file(s). Check your working tree NOW.`);
  console.log(`mutations: the sentinel at ${SENTINEL} was KEPT deliberately, so the next`);
  console.log("           run of the gate refuses rather than measuring a poisoned tree.");
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
