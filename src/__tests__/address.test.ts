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

import { describe, expect, it } from "vitest";
import { validateXrplAddress } from "../core/address.ts";

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
