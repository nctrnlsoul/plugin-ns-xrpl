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
