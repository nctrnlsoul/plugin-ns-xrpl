// Row 1 of the fail-closed table: an address that does not validate is refused,
// never passed to the network on the assumption that the node will sort it out.
//
// The checksum is the part that matters. A charset-and-length check accepts any
// string that happens to look like an address, and this project has direct
// evidence of how easy that is to produce: an address invented for the live-node
// probe on 2026-08-31 passed every structural check and came back `actMalformed`
// from rippled, because the checksum was wrong.
//
// Pure: no network, no environment, no side effects. It hashes, which is
// deterministic computation, not I/O.

import { createHash } from "node:crypto";
import { BOUNDS } from "./bounds.ts";
import { ok, type Result, refuse } from "./result.ts";

/** Ripple's base58 alphabet. Note the absence of 0, O, I and l. */
const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/** Classic addresses are 25 to 35 characters and decode to exactly 25 bytes. */
const MIN_LENGTH = 25;
const MAX_LENGTH = 35;
const DECODED_LENGTH = 25;
const PAYLOAD_LENGTH = 21;

/** The type prefix byte for a classic account address. */
const ACCOUNT_PREFIX = 0x00;

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

/**
 * Decode Ripple base58 to bytes. Returns null on any character outside the
 * alphabet rather than skipping it, because skipping an unknown character
 * silently accepts a different string than the one supplied.
 */
function decodeBase58(input: string): Uint8Array | null {
  let acc = 0n;
  for (const ch of input) {
    const digit = ALPHABET.indexOf(ch);
    if (digit < 0) return null;
    acc = acc * 58n + BigInt(digit);
  }

  const out: number[] = [];
  while (acc > 0n) {
    out.unshift(Number(acc % 256n));
    acc /= 256n;
  }

  // Each leading alphabet-zero character is a leading zero byte that the
  // bigint conversion cannot represent.
  for (const ch of input) {
    if (ch !== ALPHABET[0]) break;
    out.unshift(0);
  }

  return Uint8Array.from(out);
}

/** Constant-time-ish 4-byte compare. Not a secret, but no reason to short-circuit. */
function checksumMatches(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    // A missing byte is refused, not treated as zero. Unreachable given the
    // length check above, and written this way because `?? 0` on a comparison
    // is the coercion shape that turns an absent value into a match.
    if (x === undefined || y === undefined) return false;
    diff |= x ^ y;
  }
  return diff === 0;
}

/**
 * Validate an XRPL classic address, checksum included.
 *
 * Deliberately does NOT trim, repair or normalise. A validator that quietly
 * fixes its input accepts a class of strings the caller never checked.
 */
export function validateXrplAddress(input: unknown): Result<string> {
  if (typeof input !== "string") {
    return refuse("ADDRESS_MALFORMED", "The XRPL address was not a string, so it was refused.");
  }
  if (input.length < MIN_LENGTH || input.length > MAX_LENGTH) {
    return refuse(
      "ADDRESS_MALFORMED",
      `The XRPL address was ${input.length} characters, outside the valid range of ${MIN_LENGTH} to ${MAX_LENGTH}, so it was refused.`,
    );
  }
  if (!input.startsWith("r")) {
    return refuse(
      "ADDRESS_MALFORMED",
      "The XRPL address did not begin with r. Only classic addresses are supported, and an X-address is not assumed to be a classic one.",
    );
  }

  const decoded = decodeBase58(input);
  if (decoded === null) {
    return refuse(
      "ADDRESS_MALFORMED",
      "The XRPL address contained characters outside the Ripple base58 alphabet, so it was refused.",
    );
  }
  if (decoded.length !== DECODED_LENGTH) {
    return refuse(
      "ADDRESS_MALFORMED",
      "The XRPL address did not decode to the expected length, so it was refused.",
    );
  }
  if (decoded[0] !== ACCOUNT_PREFIX) {
    return refuse(
      "ADDRESS_MALFORMED",
      "The XRPL address did not carry the classic account prefix, so it was refused.",
    );
  }

  const payload = decoded.subarray(0, PAYLOAD_LENGTH);
  const expected = decoded.subarray(PAYLOAD_LENGTH, DECODED_LENGTH);
  const actual = sha256(sha256(payload)).subarray(0, 4);

  if (!checksumMatches(expected, actual)) {
    return refuse(
      "ADDRESS_MALFORMED",
      "The XRPL address failed its checksum, which usually means a typo. It was refused rather than looked up, because a mistyped address can be a real account belonging to someone else.",
    );
  }

  return ok(input);
}

/** True when the input is a valid classic address. For use inside validators. */
export function isValidXrplAddress(input: unknown): input is string {
  return validateXrplAddress(input).ok;
}

/**
 * The shape a classic address takes in free text. Used to FIND a candidate,
 * never to validate one: everything this matches still goes through
 * validateXrplAddress.
 */
export const ADDRESS_CANDIDATE_PATTERN = /r[1-9A-HJ-NP-Za-km-z]{24,34}/g;

/**
 * A run of address-shaped characters, INCLUDING everything that RENDERS AS
 * NOTHING between them.
 *
 * The joining class is base58, plus Default_Ignorable_Code_Point, plus
 * General_Category=Format, plus the control characters that are not whitespace,
 * plus an unpaired surrogate. The predicate is "renders as nothing", and `\s`
 * is the carve-out for the Cc members that are ordinary whitespace.
 *
 * ORDER MATTERS in the alternation and it is not stylistic: the Cf branch is
 * written FIRST because U+FEFF is a member of JavaScript's `\s`, so a
 * `(?!\s)\p{Cc}` test reached first would be the wrong shape to reason about.
 * The class branch matches U+FEFF before the control branch is ever tried.
 *
 * MEASURED, and this is why the class widened: U+0001, U+0007, U+007F, U+0085
 * and a lone U+D800 all BROKE a run under the previous class, so the provider
 * returned zero characters for a message carrying one, which is the original
 * defect. LF, TAB, CR, SPACE, NBSP, U+2028 and U+2029 still break it, and two
 * real addresses on separate lines still produce two runs rather than one.
 * U+2028 stays a BREAKER deliberately: a human sees the line break. That
 * src/core/render.ts lists it as invisible is a different job for a different
 * reason and must not be reused here.
 *
 * THIS WIDENING IS SAFE ONLY BECAUSE OF THE CHECKSUM GATE BELOW. Joining on
 * control characters admits far more runs, and what makes that harmless is that
 * a run is counted only if its visible characters are a checksum-valid classic
 * address, which is roughly a 2^-32 accident. IF THE GATE IS EVER REMOVED THIS
 * CLASS MUST REVERT TO Default_Ignorable_Code_Point UNION Cf IN THE SAME
 * COMMIT. That coupling is real and is written here so it cannot be discovered
 * only by re-deriving it.
 *
 * Carries /g because it is used with matchAll and never with test(). A /g
 * pattern makes test() STATEFUL, which src/core/render.ts records by
 * measurement; ANY_CANDIDATE_CHAR below is the one that gets tested and it
 * deliberately carries no flag.
 */
const HIDDEN_RUN_PATTERN =
  /(?:[1-9A-HJ-NP-Za-km-z\p{Default_Ignorable_Code_Point}\p{Cf}\uD800-\uDFFF]|(?!\s)\p{Cc})+/gu;

/**
 * One base58 character. NO /g, so test() means what it looks like it means.
 *
 * This is the prefilter, and it is not decoration: a run of pure U+200B carries
 * no address and the walk below would still visit every code point of it.
 * MEASURED on 99 KB of U+200B: 2.66ms without this line, 0.16ms with it, and
 * identical counts either way.
 */
const ANY_CANDIDATE_CHAR = /[1-9A-HJ-NP-Za-km-z]/;

/**
 * The 58 characters a candidate is made of, DERIVED rather than restated.
 *
 * Ripple's alphabet is a permutation of exactly the class the two patterns
 * above name, so ALPHABET is the same 58 characters and reusing it means the
 * scanner's idea of "visible" cannot drift from the decoder's.
 */
const CANDIDATE_CHARS = new Set(ALPHABET);

/**
 * The candidate shape WITHOUT /g, derived from the pattern above rather than
 * written out a second time.
 *
 * `.test()` on a /g pattern is STATEFUL: lastIndex advances on a match and
 * resets on a miss, so consecutive calls down one list return true, false,
 * true, false. src/core/render.ts records that measurement, and this file's own
 * splitter test reproduced it while it was being written. Building from
 * `.source` keeps ONE statement of the shape and drops the flag, so a narrowed
 * candidate pattern narrows this with it instead of the two drifting apart.
 */
const CANDIDATE_IN_RUN = new RegExp(ADDRESS_CANDIDATE_PATTERN.source);

/**
 * What one scan of a message found, beyond the addresses that can be read
 * normally.
 *
 * Two numbers and a flag. NO STRINGS, and that is the structural half of never
 * echoing one: the reconstructed visible characters do not leave the scanner,
 * so no later edit can print a value carrying attacker-chosen invisible
 * characters into a prompt, hand one to fetch, or key a cache on one.
 */
export interface HiddenAddressScan {
  /**
   * DISTINCT checksum-valid classic addresses whose characters are interrupted
   * by something that renders as nothing.
   */
  readonly count: number;
  /**
   * True when MAX_ADDRESS_CHECKSUMS_PER_MESSAGE stopped this plugin examining
   * every DISTINCT run it found, so `count` is a floor rather than a total.
   * Repetition of one run never sets this: the budget is charged per distinct
   * string, so a repeated word cannot exhaust it.
   */
  readonly capped: boolean;
}

/**
 * Find addresses that an invisible character hid from ADDRESS_CANDIDATE_PATTERN.
 *
 * WHY THIS EXISTS. That pattern is ASCII-only, so ONE zero-width space dropped
 * into an address makes the address invisible to the scanner as well as to the
 * reader. MEASURED against the build before this existed: a message holding
 * only "rHb9CJAWyB4rj91VRWn9" + U+200B + "6DkukG4bwdtyTh" produced zero
 * candidates, so run() returned the silent result and the prompt got zero
 * characters. Not a wrong report about a named entity: NO report, which is the
 * worse of the two on this runtime.
 *
 * THE GATE. A run is counted only when every one of these holds, and each one
 * of them can change a result on its own:
 *
 *   no candidate inside the run     the ordinary scanner already read this
 *                                   entity, so it is already reported as the
 *                                   subject, in the skipped list, or as a
 *                                   refusal. Counting it here says one omission
 *                                   twice
 *   isValidXrplAddress(visible)     the visible characters ARE a classic
 *                                   address, checksum included
 *   not already a raw candidate     the same account is not being described
 *                                   elsewhere in this very report
 *   not already examined            DISTINCT, matching the doctrine
 *                                   other_addresses_not_looked_up already
 *                                   follows, and the budget ledger in the same
 *                                   set for the same reason
 *
 * TWO CHEAP PRE-FILTERS SIT ABOVE THE GATE AND DECIDE NOTHING: `interrupted`,
 * and the length-and-leading-r window. Said plainly, because both used to be
 * written up as controls and one of them was called the whole design.
 *
 * MEASURED, 60,000 cases differentially with `interrupted` forced true: not one
 * outcome changed. The reason is structural rather than lucky. A run that is
 * NOT interrupted has all its visible characters contiguous, so if it is also
 * inside the 25..35 window and starts with `r`, those characters ARE a raw
 * candidate, and `CANDIDATE_IN_RUN` rejects it one line further down. Anything
 * `interrupted` catches, the candidate clause catches too. The length window is
 * subsumed the same way, by isValidXrplAddress, which enforces the identical
 * bounds and the identical leading `r`.
 *
 * They stay because they are cheap and they say what the scanner is for: two
 * comparisons and a boolean instead of a regex and a double SHA-256 on runs
 * that cannot qualify. What they are NOT is defence. No mutation of either can
 * fail, and a comment claiming otherwise answers an audit on a control's
 * behalf, which is the src/core/node-url.ts failure CLAUDE.md records by name.
 *
 * WHY THE CHECKSUM IS LOAD-BEARING AND NOT BELT AND BRACES. Without it this
 * function counted any 25-to-35 character base58 run carrying one soft hyphen,
 * and soft hyphens are routine in copied typeset text. MEASURED phantoms:
 * "rechtsbijstandsverzekering", "runtimeConfigurationSnapshot" and
 * "requestAuthenticationMidd" each produced a count of 1, and the message
 * "please rename runtime<U+00AD>ConfigurationSnapshot to something shorter"
 * produced an 833-character NO_READABLE_ADDRESS refusal about an XRPL account
 * that does not exist. A false statement in report content, an overstated
 * omission, and prompt pollution on an unrelated turn, which is the exact cost
 * silent() exists to avoid. The checksum takes that from routine to roughly
 * 2^-32.
 *
 * WHAT IT MUST NEVER TOUCH. isValidXrplAddress returns a BOOLEAN.
 * validateXrplAddress returns a Result carrying the reconstructed string and is
 * deliberately not called here: that Result is never materialised. `visible` is
 * a const local to one loop iteration and nothing returned from this function
 * carries it. It must never reach rpcCall or fetch, turnCacheKey or
 * skippedDigest, the lookup target, renderAccountReport's address, the report
 * text, or any log. The address that IS looked up remains candidates[0] from
 * ADDRESS_CANDIDATE_PATTERN over the raw text, unchanged.
 *
 * It does not repair, normalise or strip anything for the caller, for the
 * reason validateXrplAddress does not trim: a repaired address is an address
 * nobody typed, and looking one up would be a request about an account the
 * message never actually named. Reconstructing the visible characters in order
 * to REFUSE to use them is the opposite of repairing them into a lookup.
 *
 * THE CAP is a security bound, not a performance preference. This runs on
 * unrated conversation text before checkRateLimit and a checksum is a double
 * SHA-256, measured at 16.6ms uncapped over a hostile 99 KB message. When it
 * bites, `capped` says so and the report speaks it.
 *
 * It is charged PER DISTINCT STRING, never per run. Charged per run, ordinary
 * repetition trips it: 65 copies of one hyphenated word spent the whole budget
 * and produced a cap notice about a message holding one entity. A bound that a
 * repeated word can exhaust is not bounding the attacker, and the notice it
 * emits is a false statement in the only text the model gets.
 */
export function scanHiddenAddresses(text: unknown, candidates: unknown): HiddenAddressScan {
  if (typeof text !== "string") return { count: 0, capped: false };

  // The raw matches the ordinary scanner already found: the subject and the
  // skipped list both live in here. Exact string equality is the strongest
  // claim available and it is sound, because a base58 decode is injective, so
  // two distinct strings can never name one account. partitionOtherAddresses'
  // docstring states the same thing for the same reason.
  const rawCandidates = new Set<string>();
  if (Array.isArray(candidates)) {
    for (const c of candidates) {
      if (typeof c === "string") rawCandidates.add(c);
    }
  }

  const counted = new Set<string>();
  /**
   * Every DISTINCT visible string this message has already been charged for.
   *
   * TWO ROLES, and they are worth telling apart because only one of them
   * decides anything the report says:
   *
   *   .size   the budget ledger. It is what makes `capped` per DISTINCT run,
   *           and a repeated string cannot move it, because Set.add is
   *           idempotent
   *   .has    a work bound only. Skipping a repeat saves a double SHA-256 and
   *           changes no reported value
   *
   * ONE set rather than a set beside an integer counter, because a counter is a
   * second number that can disagree with the set, and it did: the shipped form
   * charged per RUN while `counted` deduped only what PASSED. `counted` holds
   * the strings that passed the checksum, so it can never answer either
   * question about a string that failed.
   */
  const examined = new Set<string>();
  let capped = false;

  for (const match of text.matchAll(HIDDEN_RUN_PATTERN)) {
    const run = match[0];
    if (!ANY_CANDIDATE_CHAR.test(run)) continue;

    // ONE walk, by CODE POINT rather than by UTF-16 unit, so a supplementary
    // format character such as U+E0041 is one character and not two halves.
    let visible = "";
    let interrupted = false;
    let gapAfterVisible = false;

    for (const ch of run) {
      if (CANDIDATE_CHARS.has(ch)) {
        if (gapAfterVisible) interrupted = true;
        visible += ch;
      } else if (visible !== "") {
        gapAfterVisible = true;
      }
    }

    // THE FIRST OF THE TWO PRE-FILTERS WITH NO INDEPENDENT EFFECT, and the one
    // that used to be written up as the whole design. A run that is not
    // interrupted has its visible characters contiguous, so CANDIDATE_IN_RUN
    // below rejects it for the same reason a line later. MEASURED over 60,000
    // differential cases with this forced true: not one outcome changed.
    if (!interrupted) continue;

    // THE SECOND, and the same story: isValidXrplAddress enforces this window
    // and this leading `r`, so removing either line changes no result and no
    // mutation of either alone can fail. Both stay because they turn most
    // rejections into two comparisons instead of a double SHA-256. The bound
    // that matters is the cap below, not these.
    if (visible.length < MIN_LENGTH || visible.length > MAX_LENGTH) continue;
    if (!visible.startsWith("r")) continue;

    if (CANDIDATE_IN_RUN.test(run)) continue;
    if (rawCandidates.has(visible)) continue;

    // THE ONLY BOUND ON REPEATED WORK, and it decides no reported value. Said
    // plainly, because the line below already makes every OUTPUT per-distinct
    // and it would be easy to write this one up as doing that too.
    //
    // MEASURED both ways over the same input, 20,000 repetitions of one run in
    // 586 KB: 1 checksum and 12.9ms with this line, 20,000 checksums and 67.0ms
    // without it, and `count` and `capped` IDENTICAL either way. So this saves
    // work and nothing else.
    //
    // It is not optional for that reason. The cap below counts DISTINCT strings,
    // so it never fires on repetition however long the message: at 20,000 copies
    // `capped` is still false. This line is therefore the whole bound on a
    // hostile message built from ONE run, and that message is unrated
    // conversation text arriving before checkRateLimit.
    //
    // KNOWN GAP, stated rather than left to be rediscovered: no test observes
    // this, because the only observable is wall-clock and a timing assertion in
    // this suite would be flaky. checks/mutations.ts cannot cover it either, for
    // the same reason. It is held by this comment and by nothing else.
    if (examined.has(visible)) continue;

    // Charged BEFORE the work, so a message that runs out of budget cannot
    // spend one more checksum than the bound allows.
    //
    // `examined.size` IS the charge, and that is what makes the cap per
    // DISTINCT string. A counter beside the set would be a second number that
    // can disagree with it, and it did: the shipped form incremented a
    // `checksums` integer once per RUN while `counted` deduped only the strings
    // that PASSED, so a repeated run that FAILED was charged every time.
    // MEASURED end to end: 65 repetitions of "runtime<U+00AD>Configuration-
    // Snapshot", one word and one entity, spent all 64 checksums, set `capped`,
    // and made the provider speak a 565-character refusal about an XRPL account
    // that does not exist. No checksum ever passed, so no count was wrong; the
    // CAP NOTICE was the false statement, on a turn with no XRPL content at all.
    if (examined.size >= BOUNDS.MAX_ADDRESS_CHECKSUMS_PER_MESSAGE) {
      capped = true;
      continue;
    }
    examined.add(visible);

    if (!isValidXrplAddress(visible)) continue;
    counted.add(visible);
  }

  return { count: counted.size, capped };
}

/**
 * How many DISTINCT addresses an invisible character hid, and nothing else.
 *
 * The one-number entry point, kept because it is what a consumer auditing a
 * message wants and because it is the shape the export surface documents.
 * src/provider.ts uses scanHiddenAddresses, which reports the cap in the same
 * pass rather than paying for a second one.
 */
export function countUnreadableAddressRuns(text: unknown, candidates: unknown): number {
  return scanHiddenAddresses(text, candidates).count;
}
