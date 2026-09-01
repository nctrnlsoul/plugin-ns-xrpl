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
    // Search text updated when F1 restructured the renderer. The harness caught
    // the drift itself and went RED rather than quietly testing nothing, which
    // is the whole reason a stale entry is a hard failure here.
    //
    // The path this guards also moved. It is now the LAST RESORT only: reached
    // when the header alone overruns the cap, so there are no rows left to drop.
    // A hard cut still has to be spoken, and src/__tests__/render-redproof.ts
    // pins the marker on exactly that path.
    find: "  return build(0).slice(0, BOUNDS.MAX_RENDERED_CHARS - marker.length) + marker;",
    replace: "  return build(0).slice(0, BOUNDS.MAX_RENDERED_CHARS);",
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
    // Search text updated when D6 gave speak() its second argument. The harness
    // caught the drift itself rather than quietly testing nothing.
    find: '    if ("ok" in linesResult && linesResult.ok === false) return speak(linesResult, skipped);',
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
    file: "src/provider.ts",
    // Search text updated when D6 appended the other-addresses notice here.
    find: '    text: `XRPL lookup refused. ${r.message}${others === "" ? "" : ` ${others}`}`,',
    replace: '    text: `Lookup refused. ${r.message}${others === "" ? "" : ` ${others}`}`,',
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
    file: "src/provider.ts",
    find: "    const skipped = new Set(candidates.filter((c) => c !== first)).size;",
    replace: "    const skipped = 0;",
    why: "the original defect: a message naming five accounts produced a report about one and nothing said the other four existed",
  },
  {
    id: "d6-other-addresses-counted-with-duplicates",
    file: "src/provider.ts",
    find: "    const skipped = new Set(candidates.filter((c) => c !== first)).size;",
    replace: "    const skipped = candidates.length - 1;",
    why: "the same address written twice was reported as a further account that was not looked up, and overstating an omission is the same inaccuracy as hiding one",
  },
  {
    id: "d6-threshold-off-by-one",
    file: "src/core/render.ts",
    find: '  if (n === 0) return "";',
    replace: '  if (n <= 1) return "";',
    why: "X-006 puts the threshold at ONE: dropping exactly one address is the smallest case that must be reported, and it is the case a comfortable fixture never covers",
  },
  {
    id: "d6-count-dropped-from-the-notice",
    file: "src/core/render.ts",
    find: "  return `other_addresses_not_looked_up: ${n}. The message held further text shaped like an XRPL address. Only the FIRST address was looked up; the rest were neither validated nor retrieved, so nothing in this report describes them.`;",
    replace:
      "  return `other_addresses_not_looked_up: some. The message held further text shaped like an XRPL address. Only the FIRST address was looked up; the rest were neither validated nor retrieved, so nothing in this report describes them.`;",
    why: "F2's shape applied to the new notice: a count asserted against the whole report is satisfied by any stray digit in the fixture",
  },
  {
    id: "d6-refusal-drops-the-notice",
    file: "src/provider.ts",
    find: '    text: `XRPL lookup refused. ${r.message}${others === "" ? "" : ` ${others}`}`,',
    replace: "    text: `XRPL lookup refused. ${r.message}`,",
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
    find: 'error instanceof Error ? error.name : "unknown error"',
    replace: 'error instanceof Error ? "ZZQQXX" : "unknown error"',
    why: "invariant 1's last line of defence had a test proving it SPEAKS and none reading what it said",
  },
  {
    id: "f2-duplicate-later-address-counted-twice",
    file: "src/provider.ts",
    find: "    const skipped = new Set(candidates.filter((c) => c !== first)).size;",
    replace: "    const skipped = candidates.filter((c) => c !== first).length;",
    why: "finer than d6-other-addresses-counted-with-duplicates, which the [A, A] test catches because both forms give 0 there. [A, B, B] gives 1 shipped and 2 here, and overstating an omission is the same inaccuracy as hiding one",
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
