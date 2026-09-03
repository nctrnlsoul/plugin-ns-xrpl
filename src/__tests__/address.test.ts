// Row 1 of the security pass fail-closed table:
//   "Address parses and is a valid XRPL address -> REFUSE. Never 'assume
//    classic, try anyway'."
//
// Written before src/core/address.ts exists.
//
// The checksum half is the load-bearing half. Charset-and-length validation
// alone accepts garbage that merely looks like an address, and this project has
// direct evidence: an address invented from memory for the live-node probe came
// back `actMalformed` from rippled, because its checksum was wrong. Without a
// checksum here that string reaches the network.

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ADDRESS_CANDIDATE_PATTERN,
  countUnreadableAddressRuns,
  scanHiddenAddresses,
  validateXrplAddress,
} from "../core/address.ts";
import { BOUNDS } from "../core/bounds.ts";

// Captured from the live public ledger 2026-08-31, not written from memory.
const REAL_FUNDED = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const REAL_ISSUER = "rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B";
const REAL_COUNTERPARTY = "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS";

describe("validateXrplAddress", () => {
  it("accepts real classic addresses taken from the live ledger", () => {
    for (const addr of [REAL_FUNDED, REAL_ISSUER, REAL_COUNTERPARTY]) {
      const r = validateXrplAddress(addr);
      expect(r.ok, `${addr} should be valid`).toBe(true);
      if (r.ok) expect(r.value).toBe(addr);
    }
  });

  it("REFUSES a string with a valid charset and length but a broken checksum", () => {
    // rippled itself called this actMalformed on 2026-08-31. It is exactly the
    // shape that a charset-only validator waves through.
    const r = validateXrplAddress("rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("ADDRESS_MALFORMED");
  });

  it("REFUSES a real address with one character transposed", () => {
    // Single-character corruption must not survive. This is the check that
    // catches a typo before it becomes a network request about the wrong
    // account, or a confident report about an account that does not exist.
    const corrupted = `${REAL_FUNDED.slice(0, -1)}${REAL_FUNDED.at(-1) === "h" ? "j" : "h"}`;
    expect(corrupted).not.toBe(REAL_FUNDED);
    const r = validateXrplAddress(corrupted);
    expect(r.ok).toBe(false);
  });

  it("REFUSES characters outside the Ripple base58 alphabet", () => {
    // 0, O, I and l are deliberately absent from the Ripple alphabet.
    for (const bad of ["r0OIl1111111111111111111111", "rHb9CJAWyB4rj91VRWn96DkukG4bwdty0"]) {
      const r = validateXrplAddress(bad);
      expect(r.ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES anything not starting with r", () => {
    for (const bad of [
      "XHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
      "1Hb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    ]) {
      expect(validateXrplAddress(bad).ok).toBe(false);
    }
  });

  it("REFUSES an X-address rather than assuming classic and trying anyway", () => {
    // The table's words. X-addresses are a real format this plugin does not
    // support, and guessing at one is how a request lands on the wrong account.
    const r = validateXrplAddress("X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("ADDRESS_MALFORMED");
  });

  it("REFUSES non-string input without throwing", () => {
    // Rule 10: malformed input returns BLOCK. It must not return an exception,
    // because on this runtime an exception is swallowed into silence.
    for (const bad of [null, undefined, 42, {}, [], true, Number.NaN, () => {}]) {
      const r = validateXrplAddress(bad as unknown);
      expect(r.ok, `${String(bad)} must be refused`).toBe(false);
    }
  });

  it("REFUSES the empty string and whitespace", () => {
    for (const bad of ["", "   ", "\n", "\t"]) {
      expect(validateXrplAddress(bad).ok).toBe(false);
    }
  });

  it("does not silently trim or repair input", () => {
    // A validator that trims is a validator that accepts a class of input the
    // caller never checked. Refuse and let the caller decide.
    const r = validateXrplAddress(` ${REAL_FUNDED} `);
    expect(r.ok).toBe(false);
  });

  it("REFUSES an over-long string that starts with a valid address", () => {
    expect(validateXrplAddress(`${REAL_FUNDED}${REAL_FUNDED}`).ok).toBe(false);
  });

  it("every refusal carries a non-empty message", () => {
    // Item 0: on this runtime an empty refusal is invisible to the model.
    const r = validateXrplAddress("garbage");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.message.length).toBeGreaterThan(0);
      expect(r.message.trim()).not.toBe("");
    }
  });
});

// A cold pass enumerated every number this package EMITS, replacing each with a
// word and demanding the suite go red. Both numbers in this refusal survived:
// nothing read the length it quotes, and nothing read the range it quotes.
//
// They are unreachable through the provider, because ADDRESS_CANDIDATE_PATTERN
// only matches 25 to 35 characters, so no candidate can fail the length branch.
// validateXrplAddress is an EXPORT, so a consumer reaches it directly, and a
// refusal that misreports why it refused is the same defect one layer out.
describe("the length refusal quotes numbers that are true of the input it refused", () => {
  it("quotes the ACTUAL length of the string, not a constant", () => {
    // Several lengths, all outside the valid range, each of which must appear
    // verbatim. One example would be satisfied by hardcoding that one number.
    for (const len of [1, 6, 24, 36, 200]) {
      const r = validateXrplAddress("r".repeat(len));
      expect(r.ok, `${len} characters must be refused`).toBe(false);
      if (!r.ok) expect(r.message, `${len} characters`).toContain(`was ${len} characters`);
    }
  });

  it("the range it quotes is the range it actually enforces", () => {
    // Read MIN and MAX out of the MESSAGE, then prove the validator's real
    // boundary is exactly those two numbers. Comparing the message against the
    // constants would pass for whatever the constants happened to be.
    const short = validateXrplAddress("r");
    expect(short.ok).toBe(false);
    const quoted = short.ok ? null : short.message.match(/valid range of (\d+) to (\d+)/);
    expect(quoted, "the refusal must quote two NUMBERS as its range").not.toBeNull();

    const min = Number.parseInt(String(quoted?.[1]), 10);
    const max = Number.parseInt(String(quoted?.[2]), 10);
    expect(Number.isInteger(min) && min > 0, `min was ${String(quoted?.[1])}`).toBe(true);
    expect(Number.isInteger(max) && max > min, `max was ${String(quoted?.[2])}`).toBe(true);

    // One character either side of the quoted range is refused FOR ITS LENGTH.
    for (const len of [min - 1, max + 1]) {
      const r = validateXrplAddress("r".repeat(len));
      expect(r.ok, `${len} characters must be refused`).toBe(false);
      if (!r.ok) {
        expect(r.message, `${len} characters is outside the quoted range`).toContain(
          "outside the valid range",
        );
      }
    }

    // Everything INSIDE the quoted range is still refused, because a run of r's
    // is not an address, but never for its length. That is what makes the two
    // quoted numbers the real boundary rather than decoration.
    for (let len = min; len <= max; len++) {
      const r = validateXrplAddress("r".repeat(len));
      expect(r.ok, `${len} r's is not a real address`).toBe(false);
      if (!r.ok) {
        expect(r.message, `${len} characters must not be refused for its LENGTH`).not.toContain(
          "outside the valid range",
        );
      }
    }
  });
});

// F8. ADDRESS_CANDIDATE_PATTERN is ASCII-only, so ONE invisible character
// dropped into an address makes it invisible to the scanner as well as to the
// reader. MEASURED against the shipped build: a message holding only
// "rHb9CJAWyB4rj91VRWn9" + U+200B + "6DkukG4bwdtyTh" yielded ZERO candidates,
// so run() returned the silent result, and on this runtime an empty provider
// text contributes zero characters to the prompt. Not a wrong report: NO
// report, and no marker anywhere saying an entity had been named.
//
// countUnreadableAddressRuns is the second scanner that makes that case
// speakable. It answers one question and one only: HOW MANY runs of
// address-shaped characters did this message hold that were interrupted by
// invisible or formatting characters. It returns a NUMBER and never the runs
// themselves, so no later edit can print one.
//
// The property under test, stated over a SET rather than over the reproduction:
// for every entity the message names or implies, the report either describes it
// with retrieved data or names it and says plainly that no data for it appears.
const ZWSP = "\u200B";
/** Ripple's base58 alphabet, which is a permutation of the candidate class. */
const RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/** Everything ADDRESS_CANDIDATE_PATTERN finds, with /g's stateful test() avoided. */
const candidatesIn = (text: string): string[] => text.match(ADDRESS_CANDIDATE_PATTERN) ?? [];

/**
 * The scan EXACTLY as src/provider.ts performs it: the raw candidate list goes
 * in, so a run the ordinary scanner already read is excluded here too.
 */
const hiddenIn = (text: unknown): number =>
  countUnreadableAddressRuns(text, typeof text === "string" ? candidatesIn(text) : []);

/**
 * Any address with one splitter dropped in after its 24th visible character.
 *
 * 24 is chosen so no candidate survives anywhere in the run: the prefix is one
 * short of the pattern's minimum and the suffix is at most eleven characters.
 */
const poison = (address: string, splitter: string = ZWSP) =>
  `${address.slice(0, 24)}${splitter}${address.slice(24)}`;

/**
 * Distinct valid classic addresses, BUILT rather than pasted, so a property
 * over the whole base58 alphabet can be stated without sixty chances to paste
 * a broken checksum. Every one is asserted valid before anything relies on it.
 */
function manyValidAddresses(n: number): string[] {
  const out: string[] = [];
  for (let seed = 0; out.length < n; seed++) {
    const payload = new Uint8Array(21);
    payload.set(
      new Uint8Array(
        createHash("sha256")
          .update(new Uint8Array([seed & 0xff, (seed >> 8) & 0xff]))
          .digest(),
      ).subarray(0, 20),
      1,
    );
    const full = new Uint8Array(25);
    full.set(payload, 0);
    const once = new Uint8Array(createHash("sha256").update(payload).digest());
    full.set(new Uint8Array(createHash("sha256").update(once).digest()).subarray(0, 4), 21);
    let acc = 0n;
    for (const b of full) acc = acc * 256n + BigInt(b);
    let str = "";
    while (acc > 0n) {
      str = RIPPLE_ALPHABET[Number(acc % 58n)] + str;
      acc /= 58n;
    }
    for (const b of full) {
      if (b !== 0) break;
      str = RIPPLE_ALPHABET[0] + str;
    }
    out.push(str);
  }
  return out;
}

/** REAL_FUNDED with one splitter dropped in after `k` visible characters. */
const split = (splitter: string, k: number) =>
  `${REAL_FUNDED.slice(0, k)}${splitter}${REAL_FUNDED.slice(k)}`;

describe("the unreadable-run scanner counts by UNICODE PROPERTY, not by a hand list", () => {
  // Every one of these is Default_Ignorable_Code_Point or General_Category=Cf.
  // 4,206 code points are, and the obvious hand list (zero-width, word joiner,
  // soft hyphen, BOM, the bidi overrides) covers 45 of them. The twelve at the
  // end of this list are the ones such a list misses, including all 4,096 tag
  // characters in U+E0000..U+E0FFF. Written as \u escapes, per CLAUDE.md.
  const SPLITTERS = [
    "\u200B", // ZERO WIDTH SPACE
    "\u200C", // ZERO WIDTH NON-JOINER
    "\u200D", // ZERO WIDTH JOINER
    "\u2060", // WORD JOINER
    "\u00AD", // SOFT HYPHEN
    "\uFEFF", // ZERO WIDTH NO-BREAK SPACE / BOM
    "\u202A", // LEFT-TO-RIGHT EMBEDDING
    "\u202B", // RIGHT-TO-LEFT EMBEDDING
    "\u202C", // POP DIRECTIONAL FORMATTING
    "\u202D", // LEFT-TO-RIGHT OVERRIDE
    "\u202E", // RIGHT-TO-LEFT OVERRIDE
    "\u2066", // LEFT-TO-RIGHT ISOLATE
    "\u2067", // RIGHT-TO-LEFT ISOLATE
    "\u2068", // FIRST STRONG ISOLATE
    "\u2069", // POP DIRECTIONAL ISOLATE
    "\u180E", // MONGOLIAN VOWEL SEPARATOR
    "\u200E", // LEFT-TO-RIGHT MARK
    "\u200F", // RIGHT-TO-LEFT MARK
    "\u061C", // ARABIC LETTER MARK
    "\uFE00", // VARIATION SELECTOR-1
    "\uFE0F", // VARIATION SELECTOR-16
    "\u115F", // HANGUL CHOSEONG FILLER
    "\u3164", // HANGUL FILLER
    "\uFFA0", // HALFWIDTH HANGUL FILLER
    "\u{E0041}", // TAG LATIN CAPITAL LETTER A
  ];

  it("the fixtures are what this block claims they are", () => {
    // Rule 95: prove the setup. Twenty-five DISTINCT splitters, and the address
    // they are dropped into is a real one, or every assertion below is vacuous.
    expect(new Set(SPLITTERS).size, "twenty-five distinct splitters").toBe(SPLITTERS.length);
    expect(SPLITTERS.length).toBeGreaterThan(0);
    expect(validateXrplAddress(REAL_FUNDED).ok, "the base address must be valid").toBe(true);
    expect(candidatesIn(REAL_FUNDED), "and must be found on its own").toEqual([REAL_FUNDED]);
  });

  it("counts a run interrupted by EVERY one of the twenty-five splitters", () => {
    // The test that proves the property was used rather than a list. Swap
    // \p{Default_Ignorable_Code_Point} and \p{Cf} for the obvious hand list and
    // twelve of these go to zero, U+FE0F and U+3164 and U+115F and U+FFA0 and
    // U+E0041 among them.
    for (const s of SPLITTERS) {
      const poisoned = split(s, 20);
      const cp = (s.codePointAt(0) ?? 0).toString(16).toUpperCase();
      expect(candidatesIn(poisoned), `U+${cp}: setup, no candidate survives`).toEqual([]);
      expect(hiddenIn(poisoned), `U+${cp} must be counted`).toBe(1);
    }
  });

  it("stays at zero on the same address with no splitter in it, for all of them", () => {
    // The negative control. Without it a scanner that counted every run would
    // satisfy every assertion above.
    expect(hiddenIn(REAL_FUNDED)).toBe(0);
    expect(hiddenIn(`please look up ${REAL_FUNDED} for me`)).toBe(0);
  });

  // The class is the UNION of two Unicode properties, and the twenty-five
  // splitters above pin only ONE half of it. MEASURED: deleting \p{Cf} from the
  // pattern leaves all twenty-five detected and the whole suite green, because
  // not one of them is Format-and-not-Default-Ignorable. That silently narrows
  // the class by 32 code points, sixteen of which are U+13430..U+1343F, which
  // the pattern's own docstring names by hand as covered.
  //
  // So each half gets its own test, and each names members the OTHER half does
  // not contain.
  describe("each half of the class is pinned on its own", () => {
    const IS_DI = /\p{Default_Ignorable_Code_Point}/u;
    const IS_CF = /\p{Cf}/u;

    /** Format, and NOT Default_Ignorable. All 32 of them exist; these are 12. */
    const CF_NOT_DI = [
      "\u0600", // ARABIC NUMBER SIGN
      "\u0601", // ARABIC SIGN SANAH
      "\u0605", // ARABIC NUMBER MARK ABOVE
      "\u06DD", // ARABIC END OF AYAH
      "\u070F", // SYRIAC ABBREVIATION MARK
      "\u0890", // ARABIC POUND MARK ABOVE
      "\u08E2", // ARABIC DISPUTED END OF AYAH
      "\uFFF9", // INTERLINEAR ANNOTATION ANCHOR
      "\uFFFB", // INTERLINEAR ANNOTATION TERMINATOR
      "\u{110BD}", // KAITHI NUMBER SIGN
      "\u{13430}", // EGYPTIAN HIEROGLYPH VERTICAL JOINER
      "\u{1343F}", // EGYPTIAN HIEROGLYPH END WALLED ENCLOSURE
    ];

    /** Default_Ignorable, and NOT Format. */
    const DI_NOT_CF = [
      "\u034F", // COMBINING GRAPHEME JOINER
      "\u115F", // HANGUL CHOSEONG FILLER
      "\u1160", // HANGUL JUNGSEONG FILLER
      "\u17B4", // KHMER VOWEL INHERENT AQ
      "\u180B", // MONGOLIAN FREE VARIATION SELECTOR ONE
      "\u2065", // (unassigned, reserved default-ignorable)
      "\u3164", // HANGUL FILLER
      "\uFE00", // VARIATION SELECTOR-1
      "\uFE0F", // VARIATION SELECTOR-16
      "\uFFA0", // HALFWIDTH HANGUL FILLER
      "\uFFF0", // (unassigned, reserved default-ignorable)
      "\u{E0080}", // reserved default-ignorable in the tag block
    ];

    it("the two lists really are the two halves, and neither is empty", () => {
      // Rule 95: prove the setup, with the properties read HERE rather than
      // inherited from the pattern under test. A list that turned out to be in
      // both halves would make the assertions below pass for the wrong reason.
      expect(CF_NOT_DI.length).toBeGreaterThan(0);
      expect(DI_NOT_CF.length).toBeGreaterThan(0);
      for (const c of CF_NOT_DI) {
        const cp = `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase()}`;
        expect(IS_CF.test(c), `${cp} must be Format`).toBe(true);
        expect(IS_DI.test(c), `${cp} must NOT be Default_Ignorable`).toBe(false);
      }
      for (const c of DI_NOT_CF) {
        const cp = `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase()}`;
        expect(IS_DI.test(c), `${cp} must be Default_Ignorable`).toBe(true);
        expect(IS_CF.test(c), `${cp} must NOT be Format`).toBe(false);
      }
    });

    it("counts a run interrupted by a FORMAT character that is not Default_Ignorable", () => {
      // This is the test that dies if \p{Cf} is deleted from the pattern.
      for (const c of CF_NOT_DI) {
        const cp = `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase()}`;
        const poisoned = split(c, 20);
        expect(candidatesIn(poisoned), `${cp}: setup, no candidate survives`).toEqual([]);
        expect(hiddenIn(poisoned), `${cp} must be counted`).toBe(1);
      }
    });

    it("counts a run interrupted by a DEFAULT-IGNORABLE character that is not Format", () => {
      // And this is the test that dies if the other half is deleted.
      for (const c of DI_NOT_CF) {
        const cp = `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase()}`;
        const poisoned = split(c, 20);
        expect(candidatesIn(poisoned), `${cp}: setup, no candidate survives`).toEqual([]);
        expect(hiddenIn(poisoned), `${cp} must be counted`).toBe(1);
      }
    });
  });
});

describe("the unreadable-run scanner counts the whole reachable band, position by position", () => {
  it("counts a splitter at EVERY visible index, in the band the candidate scanner cannot see", () => {
    // The sweep, and the two bands are the measurement rather than an
    // assumption. Below 25 visible characters the prefix is too short for
    // ADDRESS_CANDIDATE_PATTERN, so the message yields NO candidate at all and
    // used to produce silence: that band is this function's whole job. At 25 and
    // above the prefix IS candidate-shaped, so the entity is already reported by
    // the ordinary path and counting it here as well would state one omission
    // twice.
    //
    // The upper band asserted `toBe(1)` in the first version of this test, and
    // that was the defect rather than the assertion being weak: the report then
    // said `other_addresses_not_valid: 1` AND `addresses_hidden_by_invisible_characters: 1` about
    // one account.
    let silentBand = 0;
    let loudBand = 0;
    for (let k = 1; k <= REAL_FUNDED.length - 1; k++) {
      const poisoned = split(ZWSP, k);
      const found = candidatesIn(poisoned);

      if (k < 25) {
        expect(found, `k=${k} is below the candidate window`).toEqual([]);
        expect(hiddenIn(poisoned), `k=${k} must be counted`).toBe(1);
        silentBand++;
        continue;
      }

      expect(found, `k=${k} leaves exactly one candidate`).toHaveLength(1);
      const r = validateXrplAddress(found[0]);
      expect(r.ok, `k=${k}: a cut address must fail`).toBe(false);
      if (!r.ok) expect(r.code, `k=${k}`).toBe("ADDRESS_MALFORMED");
      expect(
        hiddenIn(poisoned),
        `k=${k}: the candidate scanner already read this run, so it must NOT be counted twice`,
      ).toBe(0);
      loudBand++;
    }
    // Rule 95: prove the sweep reached BOTH bands. One band alone would test
    // half the property and read as the whole of it.
    expect(silentBand, "the sweep must cover the silent band").toBe(24);
    expect(loudBand, "and the loud band").toBe(9);
  });

  it("THRESHOLD: one hidden address is 1, two DISTINCT ones are 2, and none is 0", () => {
    expect(hiddenIn("pay nobody today")).toBe(0);
    expect(hiddenIn(`pay ${poison(REAL_FUNDED)} today`)).toBe(1);
    expect(hiddenIn(`pay ${poison(REAL_FUNDED)} and ${poison(REAL_COUNTERPARTY)} today`)).toBe(2);
  });

  it("counts the SAME hidden address named twice as ONE, in either poisoned form", () => {
    // DISTINCT, matching the doctrine other_addresses_not_looked_up already
    // follows. Two poisonings of one account are one omission, and two runs
    // that differ only in WHERE the splitter sits are still one account.
    expect(hiddenIn(`${poison(REAL_FUNDED)} and again ${poison(REAL_FUNDED)}`)).toBe(1);
    expect(hiddenIn(`${split(ZWSP, 20)} and again ${split(ZWSP, 12)}`)).toBe(1);
  });

  it("counts a run carrying MANY splitters exactly once", () => {
    // A run is a run. Counting characters instead of runs would overstate the
    // omission, and overstating one is the same inaccuracy as hiding one.
    const many = REAL_FUNDED.split("").join(ZWSP);
    expect(many.length).toBeGreaterThan(REAL_FUNDED.length);
    expect(hiddenIn(many)).toBe(1);
  });
});

// THE GATE IS A CHECKSUM, and this block is why it had to be.
//
// MEASURED against the version without it: ANY run of 25 to 35 base58-class
// characters starting with a lowercase r and carrying one soft hyphen was
// counted, and soft hyphens are routine in copied typeset text. Three real
// words did it. End to end, the message
//   "please rename runtime<U+00AD>ConfigurationSnapshot to something shorter"
// produced an 833-character NO_READABLE_ADDRESS refusal about an XRPL account
// that does not exist: a false statement in report content, an overstated
// omission, and prompt pollution on a turn with no XRPL content at all, which
// is the exact cost silent() exists to avoid.
describe("the gate is a CHECKSUM, so ordinary text can never trip the notice", () => {
  const SHY = "\u00AD";

  /** The three phantoms, MEASURED as counting 1 before the gate existed. */
  const PHANTOMS = [
    "rechtsbijstandsverzekering",
    "runtimeConfigurationSnapshot",
    "requestAuthenticationMidd",
  ];

  it("the phantom fixtures are what this block claims they are", () => {
    // Rule 95: prove the setup. Each must really be base58-class, really start
    // with r, and really land inside the 25..35 window, or the assertions below
    // pass because the words are uninteresting rather than because of the gate.
    for (const word of PHANTOMS) {
      const run = word.match(/^[1-9A-HJ-NP-Za-km-z]+/)?.[0] ?? "";
      expect(run.startsWith("r"), `${word} must start with r`).toBe(true);
      expect(run.length, `${word} must be inside the window`).toBeGreaterThanOrEqual(25);
      expect(run.length, word).toBeLessThanOrEqual(35);
      expect(validateXrplAddress(run).ok, `${word} must NOT be a real address`).toBe(false);
    }
  });

  it("counts NOTHING for ordinary words carrying a soft hyphen", () => {
    for (const word of PHANTOMS) {
      const poisoned = `${word.slice(0, 5)}${SHY}${word.slice(5)}`;
      expect(hiddenIn(poisoned), word).toBe(0);
      expect(hiddenIn(`please rename ${poisoned} to something shorter`), word).toBe(0);
    }
  });

  it("counts NOTHING for a poisoned run whose visible characters fail the checksum", () => {
    // One character transposed is the whole difference. This is the same shape
    // that IS counted below, so the checksum is provably the only thing
    // separating them.
    const broken = `${REAL_FUNDED.slice(0, -1)}${REAL_FUNDED.at(-1) === "h" ? "j" : "h"}`;
    expect(broken).not.toBe(REAL_FUNDED);
    expect(validateXrplAddress(broken).ok, "setup: it must really fail").toBe(false);
    expect(hiddenIn(poison(broken))).toBe(0);
  });

  it("POSITIVE CONTROL: the identical shape with a REAL address is counted", () => {
    // Without this the block above is satisfied by a scanner that counts
    // nothing at all.
    expect(hiddenIn(poison(REAL_FUNDED))).toBe(1);
    expect(hiddenIn(poison(REAL_COUNTERPARTY))).toBe(1);
    expect(hiddenIn(poison(REAL_ISSUER))).toBe(1);
  });

  it("the visible set is EXACTLY the base58 charset, proved one character at a time", () => {
    // The previous version of this could not fail. It probed with a run that
    // was 26 visible when the character counted and 25 when it did not, and
    // BOTH are inside the window, so removing a character from the set changed
    // no assertion. Under the checksum gate a missing character changes the
    // reconstructed string, so the checksum fails and the count drops to zero:
    // every character is now load-bearing on its own.
    const built = manyValidAddresses(160);
    for (const a of built) expect(validateXrplAddress(a).ok, a).toBe(true);

    const witness = new Map<string, string>();
    for (const address of built) {
      // Only characters at or past index 24 sit AFTER the splitter, but every
      // character of the reconstruction feeds the checksum, so any position
      // proves membership.
      for (const ch of address) if (!witness.has(ch)) witness.set(ch, address);
    }
    // Rule 95: prove the setup covered the whole alphabet before asserting.
    expect(witness.size, "every one of the 58 characters needs a witness").toBe(58);

    for (const [ch, address] of witness) {
      expect(hiddenIn(poison(address)), `${ch} must count as visible`).toBe(1);
    }
  });

  it("refuses a non-string without throwing, and claims nothing about it", () => {
    for (const bad of [null, undefined, 42, {}, [], true, Number.NaN, () => {}]) {
      expect(hiddenIn(bad as unknown), String(bad)).toBe(0);
    }
  });
});

// FINDING B. The joining class had to widen, because characters that render as
// nothing were BREAKING a run and producing total silence.
//
// MEASURED against the previous class: U+0001, U+0007, U+007F, U+0085 and a
// lone U+D800 each broke the run, so the provider returned text.length 0 for a
// message carrying one, which is the original defect this whole change exists
// to remove.
describe("anything that renders as nothing JOINS a run; anything a human sees BREAKS it", () => {
  const cp = (n: number) => String.fromCodePoint(n);

  it("JOINS across a control character or a lone surrogate", () => {
    for (const point of [0x0001, 0x0007, 0x001f, 0x007f, 0x0085, 0x009f, 0xd800, 0xdfff]) {
      const hex = `U+${point.toString(16).toUpperCase().padStart(4, "0")}`;
      expect(hiddenIn(poison(REAL_FUNDED, cp(point))), `${hex} must join`).toBe(1);
    }
  });

  it("BREAKS on whitespace and on anything a reader can see", () => {
    // The negative control, and the carve-out that keeps the class honest: the
    // predicate is "renders as nothing", so the Cc members that are ordinary
    // whitespace are excluded. U+2028 stays a BREAKER deliberately -- a human
    // sees the line break -- even though src/core/render.ts lists it as
    // invisible for a different job.
    for (const point of [
      0x000a, 0x0009, 0x000b, 0x000c, 0x000d, 0x0020, 0x00a0, 0x2028, 0x2029, 0x3000, 0x2007,
      0x202f,
    ]) {
      const hex = `U+${point.toString(16).toUpperCase().padStart(4, "0")}`;
      expect(hiddenIn(poison(REAL_FUNDED, cp(point))), `${hex} must break`).toBe(0);
    }
  });

  it("does not join two real addresses across a newline", () => {
    const text = `${REAL_FUNDED}\n${REAL_COUNTERPARTY}`;
    expect(candidatesIn(text), "setup: both are found normally").toEqual([
      REAL_FUNDED,
      REAL_COUNTERPARTY,
    ]);
    expect(hiddenIn(text), "and neither is a hidden address").toBe(0);
  });

  it("a PAIRED surrogate is a visible character and breaks the run", () => {
    // Only an UNPAIRED surrogate renders as nothing. An emoji is one code point
    // that a reader can see, so it must break exactly as a letter would.
    expect(hiddenIn(poison(REAL_FUNDED, cp(0x1f600)))).toBe(0);
  });
});

// THE COST BOUND. This runs on unrated conversation text before checkRateLimit
// and a checksum is a double SHA-256, measured at 16.6ms over a hostile 99 KB
// message. An omission this plugin chose for its own convenience is still an
// omission, so the cap is SPOKEN.
describe("the checksum budget is bounded, and the bound is stated when it bites", () => {
  const CAP = BOUNDS.MAX_ADDRESS_CHECKSUMS_PER_MESSAGE;

  it("does NOT report a cap for a message inside the budget", () => {
    const built = manyValidAddresses(CAP);
    const text = built.map((a) => poison(a)).join(" ");
    const scan = scanHiddenAddresses(text, candidatesIn(text));
    expect(scan.count, "every one of them is counted").toBe(CAP);
    expect(scan.capped, "and nothing was given up").toBe(false);
  });

  it("THRESHOLD: exactly ONE run past the budget sets the flag", () => {
    const built = manyValidAddresses(CAP + 1);
    const text = built.map((a) => poison(a)).join(" ");
    const scan = scanHiddenAddresses(text, candidatesIn(text));
    expect(scan.capped, "one over the budget must say so").toBe(true);
    expect(scan.count, "and the count is a floor, never more than the budget").toBe(CAP);
  });

  it("never attempts more than the budget, however large the message", () => {
    const built = manyValidAddresses(CAP * 3);
    const text = built.map((a) => poison(a)).join(" ");
    const scan = scanHiddenAddresses(text, candidatesIn(text));
    expect(scan.count).toBeLessThanOrEqual(CAP);
    expect(scan.capped).toBe(true);
  });
});

// DEFECT 1 of the narrow repair, and the block above could not see it. Every
// fixture there is a list of DISTINCT addresses, so per-run and per-distinct-run
// charging agree on all three of them.
//
// The charge read `counted.has(visible)`, and `counted` holds only the strings
// that PASSED the checksum. A repeated run that FAILED was therefore never
// recognised as a repeat and was charged again on every repetition.
//
// MEASURED end to end against that form: 65 repetitions of one hyphenated word,
// ONE entity, spent all 64 checksums, set `capped`, and the provider answered a
// 565-character NO_READABLE_ADDRESS refusal about an XRPL account that does not
// exist. No checksum ever passed, so no count was wrong. The CAP NOTICE was the
// false statement, and it says the report is INCOMPLETE, on a turn that had no
// XRPL content in it at all.
describe("the checksum budget is charged per DISTINCT run, never per run", () => {
  const CAP = BOUNDS.MAX_ADDRESS_CHECKSUMS_PER_MESSAGE;
  /** Written as an escape, never as the character. CLAUDE.md, and the lint. */
  const SHY = "\u00AD";

  /** The measured reproduction: one phantom word carrying one soft hyphen. */
  const REPEATED = `runtime${SHY}ConfigurationSnapshot`;

  /** Distinct runs that are address-shaped and are NOT addresses. */
  const distinctBroken = (n: number) =>
    manyValidAddresses(n).map((a) => poison(`${a.slice(0, -1)}${a.at(-1) === "h" ? "j" : "h"}`));

  it("the repetition fixture is what this block claims it is", () => {
    // Rule 95: prove the setup. If the word were outside the window, or held a
    // candidate, or happened to be a real address, every assertion below would
    // pass for a reason this block does not name.
    const visible = [...REPEATED].filter((c) => c !== SHY).join("");
    expect(visible.startsWith("r"), "must start with r").toBe(true);
    expect(visible.length, "must be inside the window").toBeGreaterThanOrEqual(25);
    expect(visible.length).toBeLessThanOrEqual(35);
    expect(validateXrplAddress(visible).ok, "must NOT be a real address").toBe(false);
    expect(candidatesIn(REPEATED), "and must yield no candidate of its own").toEqual([]);
  });

  it("THE REPRODUCTION: 65 repetitions of ONE word count nothing and cap nothing", () => {
    const text = Array.from({ length: CAP + 1 }, () => REPEATED).join(" ");
    const scan = scanHiddenAddresses(text, candidatesIn(text));
    expect(scan.count, "no checksum passes, so there is nothing to count").toBe(0);
    expect(scan.capped, "and one repeated word must never exhaust the budget").toBe(false);
  });

  it("THRESHOLD: the smallest repetition that used to trip it does not trip it", () => {
    // CAP+1 is what was measured, but the boundary is what must hold. Charged
    // per run, exactly CAP+1 copies is the smallest message that sets the flag,
    // so this is the case that separates the two forms by one repetition.
    for (const reps of [CAP, CAP + 1, CAP * 4]) {
      const text = Array.from({ length: reps }, () => REPEATED).join(" ");
      const scan = scanHiddenAddresses(text, candidatesIn(text));
      expect(scan.capped, `${reps} copies of one word must not cap`).toBe(false);
      expect(scan.count, `${reps} copies of one word must count nothing`).toBe(0);
    }
  });

  it("repetition of runs ALREADY EXAMINED never consumes budget", () => {
    // The property stated over valid addresses rather than over the phantom, so
    // it is not satisfied by a scanner that simply never charges for a failure.
    // Exactly CAP distinct accounts, each written five times: 320 runs, 64
    // entities, and the budget is charged 64 times.
    const once = manyValidAddresses(CAP).map((a) => poison(a));
    const text = [...once, ...once, ...once, ...once, ...once].join(" ");
    const scan = scanHiddenAddresses(text, candidatesIn(text));
    expect(scan.count, "still exactly the distinct accounts").toBe(CAP);
    expect(scan.capped, "and five times the runs is still inside the budget").toBe(false);
  });

  it("counts a repeated hidden address ONCE, never once per repetition", () => {
    // Overstating an omission is the same class of inaccuracy as hiding one, so
    // the distinctness this charge now also enforces is asserted directly.
    const twice = `${poison(REAL_FUNDED)} and again ${poison(REAL_FUNDED)}`;
    expect(hiddenIn(twice), "one account, one omission").toBe(1);
  });

  it("POSITIVE CONTROL: the bound still bites on that many DISTINCT failing runs", () => {
    // Without this the whole block is satisfied by a cap that never fires at
    // all. These runs are distinct and every one of them fails its checksum, so
    // the charge is what fires the flag rather than anything that succeeded.
    const built = distinctBroken(CAP + 1);
    expect(new Set(built).size, "setup: they must really be distinct").toBe(CAP + 1);
    for (const run of built) {
      const visible = [...run].filter((c) => c !== ZWSP).join("");
      expect(validateXrplAddress(visible).ok, "setup: none may be a real address").toBe(false);
    }
    const text = built.join(" ");
    expect(candidatesIn(text), "setup: no candidate survives any of them").toEqual([]);

    const scan = scanHiddenAddresses(text, candidatesIn(text));
    expect(scan.capped, "distinct runs past the budget must still say so").toBe(true);
    expect(scan.count, "and none of them passed, so none is counted").toBe(0);
  });
});

// The two exclusions are INDEPENDENT, and each is tested with the other unable
// to fire. A single test that satisfied both at once would not tell them apart.
describe("an account already reported elsewhere is never reported twice", () => {
  it("the candidate-in-run clause holds with an EMPTY raw candidate list", () => {
    const text = `${REAL_FUNDED}${ZWSP}a`;
    expect(candidatesIn(text), "setup: the ordinary scanner reads this run").toEqual([REAL_FUNDED]);
    expect(
      countUnreadableAddressRuns(text, []),
      "nothing in the raw list, so only the in-run clause can catch it",
    ).toBe(0);
  });

  it("the raw-candidate clause holds when the run contains NO candidate", () => {
    // The ruling's measured case: `compare A and A-with-a-splitter` printed
    // `address: A` with a real balance AND said an address hidden by invisible
    // characters was never looked up and no balance may be stated for it. One
    // report, both claims, one account. The poisoned run holds no candidate, so
    // the in-run clause cannot catch this and only the raw list can.
    const same = `compare ${REAL_FUNDED} and ${poison(REAL_FUNDED)}`;
    expect(candidatesIn(same), "setup: the run itself yields nothing").toEqual([REAL_FUNDED]);
    expect(hiddenIn(same), "the account is already described, so it is not counted again").toBe(0);

    const different = `compare ${REAL_FUNDED} and ${poison(REAL_COUNTERPARTY)}`;
    expect(hiddenIn(different), "a DISTINCT poisoned account is still counted").toBe(1);
  });
});

// The rule the two findings above share, stated once: a run is counted only
// when NO candidate could be extracted from that same run. If one could, the
// entity is already reported by the ordinary path, and counting it here as well
// says one omission twice.
//
// This block is THRESHOLD cases only. The adjacency block below is the
// comfortable version of the same idea and it is the reason this went unnoticed:
// its fixture is 68 visible characters, which can never enter the 25..35 window,
// so it could not have caught either defect.
describe("a run the candidate scanner already read is NOT counted a second time", () => {
  it("THRESHOLD: visible === 35 with a valid address inside it is NOT counted", () => {
    // MEASURED as a defect: the report carried `address: A` with a real balance
    // AND a line saying no address was read from that run and that the account
    // described was not taken from it. One report, both claims, about one run.
    // This is verbatim the defect partitionOtherAddresses' docstring names.
    const cases: Array<[string, string]> = [
      ["one base58 character after a 34-character address", `${REAL_FUNDED}${ZWSP}a`],
      ["one base58 character before it", `r${ZWSP}${REAL_FUNDED}`],
      ["two after a 33-character prefix", `${REAL_FUNDED.slice(0, 33)}${ZWSP}ab`],
    ];
    for (const [label, text] of cases) {
      // Rule 95: prove the setup. Each of these really is 35 visible
      // characters, so it really is inside the window, or the assertion below
      // passes for the wrong reason.
      const visible = [...text].filter((c) => c !== ZWSP).length;
      expect(visible, `${label}: setup, must be inside the window`).toBe(35);
      expect(hiddenIn(text), `${label} must NOT be counted`).toBe(0);
    }
  });

  it("THRESHOLD: the same width WITHOUT a candidate in it is still counted", () => {
    // The negative control, and it is what keeps the rule from being "never
    // count anything at 35". A poisoned 33-character address holds no candidate
    // anywhere in its run, so the in-run clause cannot fire and it must speak.
    //
    // The previous version of this used 35 synthetic characters, which the
    // checksum gate now refuses for a different reason entirely. A test that
    // passes for a reason it does not name is a test that has stopped measuring
    // what it claims.
    expect(REAL_ISSUER.length, "setup: a real address of a different length").toBe(33);
    expect(candidatesIn(poison(REAL_ISSUER)), "setup: no candidate in the run").toEqual([]);
    expect(hiddenIn(poison(REAL_ISSUER))).toBe(1);
  });

  it("counts a poisoned address ONCE, never as two independent omissions", () => {
    // The second half, and it was measured on the report: a splitter at visible
    // index 25 or later leaves a candidate-shaped prefix, so the same account
    // was reported as an invalid candidate AND as an unreadable run. The message
    // named ONE further account.
    for (let k = 25; k <= 33; k++) {
      const poisoned = split(ZWSP, k);
      const found = candidatesIn(poisoned);
      expect(found, `k=${k}: setup, the ordinary scanner reads this run`).toHaveLength(1);
      expect(hiddenIn(poisoned), `k=${k}: exactly one report, not two`).toBe(0);
    }
  });
});

describe("a splitter merely BESIDE an address is not a second entity", () => {
  it("counts NOTHING for adjacency, and the address is still found in every case", () => {
    // What stops this is the CANDIDATE-IN-RUN clause, not `interrupted`. A
    // splitter touching an address changes nothing about whether the address
    // can be read, so the ordinary scanner still finds it inside the very run
    // being examined, and a run that already yielded a candidate is never
    // counted. Counting one would put a second omission into a report where
    // only one entity exists, and overstating an omission is the same
    // inaccuracy as hiding one.
    //
    // `interrupted` is written up in scanHiddenAddresses as a pre-filter that
    // DECIDES NOTHING, and this block is where that claim is easiest to check:
    // every case below is also rejected one line further down. It used to be
    // described here as what stops this, and a 60,000-case differential with it
    // forced true changed no outcome at all.
    const cases: Array<[string, string, string[]]> = [
      ["immediately before", `${ZWSP}${REAL_FUNDED}`, [REAL_FUNDED]],
      ["immediately after", `${REAL_FUNDED}${ZWSP}`, [REAL_FUNDED]],
      ["elsewhere in the message", `look${ZWSP} up ${REAL_FUNDED} now`, [REAL_FUNDED]],
      [
        "joining two valid addresses",
        `${REAL_FUNDED}${ZWSP}${REAL_COUNTERPARTY}`,
        [REAL_FUNDED, REAL_COUNTERPARTY],
      ],
    ];
    for (const [label, text, expected] of cases) {
      expect(hiddenIn(text), `${label} must count nothing`).toBe(0);
      expect(candidatesIn(text), `${label}: the address is still found`).toEqual(expected);
    }
  });
});

describe("the unreadable-run scanner does not fire on ordinary text", () => {
  it("counts ZERO across a corpus of things people actually paste", () => {
    // This is the test that stops a FALSE statement in report content. The
    // notice says a run of address-shaped characters was unreadable; a count
    // produced by a URL or an emoji would be a claim about an entity the message
    // never held, in the only text the model gets when a lookup fails.
    const INNOCENT: Array<[string, string]> = [
      ["English prose", "please could you look up the balance on my account for me today"],
      ["a 64-char hex digest", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
      ["a git SHA-1", "e83c5163316f89bfbde7d9ab23ca2e25604af290"],
      ["a base64 blob", "VGhpcyBpcyBhIHRlc3QgYmxvYiB3aXRoIHBhZGRpbmc9PQ=="],
      ["an https URL", "https://xrplcluster.com/some/path?query=1&other=2"],
      ["a Windows path", "C:\\Users\\brian\\Projects\\plugin-ns-xrpl\\src\\core"],
      ["a POSIX path", "/usr/local/share/node_modules/.bin/vitest"],
      ["a UUID", "11111111-2222-4333-8444-555555555555"],
      ["an emoji with a variation selector", "shipping it \u2764\uFE0F right now"],
      ["a ZWJ emoji family", "family \uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC66 photo"],
      [
        "Arabic with an ARABIC LETTER MARK",
        "\u0645\u0631\u062D\u0628\u0627\u061C \u0627\u0644\u0639\u0627\u0644\u0645",
      ],
      ["a long sentence with no address in it", "a".repeat(400)],
      ["the empty string", ""],
    ];
    // Rule 95: a loop over an empty list passes vacuously.
    expect(INNOCENT.length).toBeGreaterThan(0);
    for (const [label, text] of INNOCENT) {
      expect(hiddenIn(text), `${label} must count nothing`).toBe(0);
    }
  });
});

// A KNOWN GAP, pinned as MEASURED BEHAVIOUR and not as an endorsement.
//
// A homoglyph, a combining mark and a fullwidth form all defeat
// ADDRESS_CANDIDATE_PATTERN in the same way an invisible character does, and
// none of them is Default_Ignorable_Code_Point or Cf, so the scanner above does
// not see them either. Both counts are zero and the message goes silent.
//
// It is written down because an unrecorded gap is rediscovered as new. Closing
// it means deciding what "address-shaped" means for a character that is VISIBLE
// and wrong, which is a different question from the one this scanner answers,
// and a wider class would start counting ordinary prose.
describe("KNOWN GAP: a VISIBLE substitution is still silent, and this pins that", () => {
  it("is silent for every class this scanner deliberately does not cover", () => {
    // The list, MEASURED and named so the next audit does not rediscover any of
    // it as new. Each of these breaks a base58 run exactly the way a zero-width
    // space does, and none of them is Default_Ignorable_Code_Point or Format,
    // so this scanner does not see them and the message produces nothing.
    //
    // U+2028 and U+2029 are the sharpest of them: src/core/render.ts CLASSIFIES
    // both as invisible and strips them from a ledger value, so two files in
    // this package hold different ideas of what "invisible" means. That
    // disagreement is now written down in render.ts's own docstring as well.
    const SILENT: Array<[string, string]> = [
      ["U+2028 LINE SEPARATOR", "\u2028"],
      ["U+2029 PARAGRAPH SEPARATOR", "\u2029"],
      ["U+0489 COMBINING CYRILLIC MILLIONS SIGN", "\u0489"],
      ["U+20E3 COMBINING ENCLOSING KEYCAP", "\u20E3"],
      ["U+2800 BRAILLE PATTERN BLANK", "\u2800"],
      ["U+00A0 NO-BREAK SPACE", "\u00A0"],
      ["U+2007 FIGURE SPACE", "\u2007"],
      ["U+202F NARROW NO-BREAK SPACE", "\u202F"],
      ["U+3000 IDEOGRAPHIC SPACE", "\u3000"],
    ];
    expect(SILENT.length).toBeGreaterThan(0);
    for (const [label, c] of SILENT) {
      const poisoned = split(c, 20);
      expect(candidatesIn(poisoned), `${label}: measured, no candidate`).toEqual([]);
      expect(hiddenIn(poisoned), `${label}: measured, no counted run`).toBe(0);
    }
  });

  it("yields no candidate and no counted run for a homoglyph, a combining mark or a fullwidth form", () => {
    const cases: Array<[string, string]> = [
      // CYRILLIC CAPITAL LETTER EN, in place of the H at index 1.
      ["a Cyrillic homoglyph", `r\u041D${REAL_FUNDED.slice(2)}`],
      // COMBINING ACUTE ACCENT after the twentieth visible character.
      ["a combining mark", `${REAL_FUNDED.slice(0, 20)}\u0301${REAL_FUNDED.slice(20)}`],
      // FULLWIDTH LATIN CAPITAL LETTER D, in place of the D at index 21.
      ["a fullwidth form", `${REAL_FUNDED.slice(0, 21)}\uFF24${REAL_FUNDED.slice(22)}`],
    ];
    for (const [label, text] of cases) {
      expect(candidatesIn(text), `${label}: measured, no candidate`).toEqual([]);
      expect(hiddenIn(text), `${label}: measured, no counted run`).toBe(0);
    }
  });
});
