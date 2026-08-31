// Finding M-5: "the plan validates the address and treats the node response as
// trusted". The node response is the second untrusted input.
//
// These functions take the RAW parsed body. Transport does not touch it first,
// because a guard placed downstream of a coercion is not a guard: if Transport
// shaped the response before Core saw it, Core's guard could never fire.
//
// They are plain exported functions, not closures inside the provider object,
// per rule 42. A validator hidden inside a closure lands in the one place a
// suite cannot reach.
//
// The failure shape being prevented, in the security pass's own words:
//     balance = (response or {}).get("account_data", {}).get("Balance", 0)
// Every fallback fires and the plugin reports "this account holds 0 XRP" with
// total confidence. There is no correct default for a balance. Absence is
// refused, never defaulted.
//
// MEASURED against the live node 2026-08-31, and this is the trap that makes the
// whole module necessary: rippled answers errors with HTTP 200 and puts the
// failure in the body. `if (!res.ok) throw` sees a healthy response.

import { isValidXrplAddress } from "./address.ts";
import { BOUNDS } from "./bounds.ts";
import { ok, type Result, refuse } from "./result.ts";

export interface AccountInfo {
  readonly address: string;
  /** Drops, as the node sent it. Kept as a string: drops exceed 2^53. */
  readonly balanceDrops: string;
  readonly ledgerIndex: number;
  readonly ownerCount: number;
  readonly sequence: number;
}

export interface TrustLine {
  readonly account: string;
  readonly balance: string;
  readonly currency: string;
  readonly limit: string;
}

export interface AccountLines {
  readonly lines: readonly TrustLine[];
  readonly ledgerIndex: number;
  /**
   * Lines the node returned that this validator could not read, so they were
   * omitted. Counted rather than ignored: the caller reports the number, so a
   * shortened list never reads as a complete one.
   */
  readonly droppedLines: number;
  readonly marker?: unknown;
}

/** A real object, not an array, not null, and not something with a hostile prototype. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Read an OWN property. Never inherited.
 *
 * If a validator reads through the prototype chain, a polluted Object.prototype
 * supplies the field and the guard passes on data that is not there.
 */
function own(obj: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

/** Drops are a run of digits. No sign, no exponent, no decimal point, no spaces. */
const DROPS_PATTERN = /^[0-9]+$/;

/**
 * Ceiling on the number of digits in a drops balance.
 *
 * The total XRP supply is 100 billion XRP, which is 1e17 drops: 18 digits. Any
 * longer value is not a balance this ledger can produce.
 *
 * Added after an adversarial red-proof. The pattern above accepts a run of
 * digits of ANY length, and the account balance is the one ledger-sourced value
 * that was not length-bounded anywhere. A hostile or broken node returning a
 * 50,000-digit Balance produced a report that the total size cap then truncated,
 * so the balance crowded out every other field and the truncation notice with
 * it. The size cap held; the report became useless. Bound the input instead of
 * relying on the output cap to clean up after it.
 */
const MAX_DROPS_DIGITS = 20;

/**
 * A drops balance the ledger could actually have produced.
 *
 * Named rather than inlined so the guard has one place to be read, one place to
 * be broken, and one line for checks/mutations.ts to target. An unnamed
 * multi-line condition is a guard nothing can point at.
 */
function isDropsBalance(v: unknown): v is string {
  return typeof v === "string" && v.length <= MAX_DROPS_DIGITS && DROPS_PATTERN.test(v);
}

/**
 * Trust line balances and limits, as the ledger actually emits them.
 *
 * The exponent is not theoretical and is not an edge case. MEASURED against the
 * live node 2026-08-31: 2 of 300 trust lines on a real issuer account carried
 * balances like "-4263500000000000e-27". An earlier version of this pattern had
 * no exponent branch, and because one bad line refused the whole list, a
 * completely legitimate account produced a total refusal. Found by running the
 * real path, not by any unit test, which is why kickoff step 9 exists.
 */
const DECIMAL_PATTERN = /^-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?$/;

/** Nothing legitimate is longer than this, and it keeps hostile input small. */
const MAX_NUMERIC_CHARS = 48;

function isLedgerNumber(v: unknown): v is string {
  return typeof v === "string" && v.length <= MAX_NUMERIC_CHARS && DECIMAL_PATTERN.test(v);
}

/**
 * Unwrap the JSON-RPC envelope and refuse every error form.
 *
 * Returns the `result` object only when the node reported success on a
 * VALIDATED ledger.
 */
function openEnvelope(raw: unknown): Result<Record<string, unknown>> {
  if (!isPlainObject(raw)) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node returned something that was not a JSON object, so the lookup was refused rather than guessed at.",
    );
  }

  const result = own(raw, "result");
  if (!isPlainObject(result)) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node response had no result object, so the lookup was refused.",
    );
  }

  // rippled reports errors at HTTP 200 with the failure in the body.
  const status = own(result, "status");
  const error = own(result, "error");

  if (typeof error === "string" && error !== "") {
    if (error === "actNotFound") {
      return refuse(
        "ACCOUNT_NOT_FOUND",
        "That XRPL account does not exist on the validated ledger. The ledger has no record of it, which is different from an account that exists and holds nothing.",
      );
    }
    if (error === "actMalformed") {
      return refuse(
        "ADDRESS_MALFORMED",
        "The XRPL node rejected that address as malformed, so no balance was retrieved.",
      );
    }
    return refuse(
      "LEDGER_ERROR",
      "The XRPL node reported an error for that lookup, so no ledger data was retrieved.",
    );
  }

  if (status !== "success") {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node did not report success for that lookup, so the response was refused.",
    );
  }

  // validated:false means the ledger can still change. Reporting it as fact
  // reports a guess. Strict === true, so a missing flag refuses too.
  if (own(result, "validated") !== true) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node did not confirm the data came from a validated ledger, so it was refused rather than reported as fact.",
    );
  }

  return ok(result);
}

function readLedgerIndex(result: Record<string, unknown>): Result<number> {
  const idx = own(result, "ledger_index");
  if (typeof idx !== "number" || !Number.isFinite(idx)) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node response carried no usable ledger index, so it was refused.",
    );
  }
  return ok(idx);
}

/**
 * Validate an `account_info` response against the address that was actually
 * asked about.
 */
export function validateAccountInfoResponse(
  raw: unknown,
  expectedAddress: string,
): Result<AccountInfo> {
  const envelope = openEnvelope(raw);
  if (!envelope.ok) return envelope;
  const result = envelope.value;

  const accountData = own(result, "account_data");
  if (!isPlainObject(accountData)) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node response contained no account data, so no balance was reported.",
    );
  }

  // A response about a different account is either a bug or an attack, and
  // either way it is not the answer to the question that was asked.
  const account = own(accountData, "Account");
  if (typeof account !== "string" || account !== expectedAddress) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node answered about a different account than the one requested, so the response was refused.",
    );
  }

  const balance = own(accountData, "Balance");
  if (!isDropsBalance(balance)) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node did not return a readable balance for that account, so no balance is being reported. This is not a balance of zero.",
    );
  }

  const ledgerIndex = readLedgerIndex(result);
  if (!ledgerIndex.ok) return ledgerIndex;

  const ownerCountRaw = own(accountData, "OwnerCount");
  const sequenceRaw = own(accountData, "Sequence");
  const ownerCount =
    typeof ownerCountRaw === "number" && Number.isFinite(ownerCountRaw) ? ownerCountRaw : -1;
  const sequence =
    typeof sequenceRaw === "number" && Number.isFinite(sequenceRaw) ? sequenceRaw : -1;

  return ok({
    address: account,
    balanceDrops: balance,
    ledgerIndex: ledgerIndex.value,
    ownerCount,
    sequence,
  });
}

/**
 * Validate an `account_lines` response.
 *
 * The split, and it was corrected once already after the live run.
 *
 * ENVELOPE problems refuse everything: a wrong status, an unvalidated ledger, or
 * trust lines for the wrong account all mean the response as a whole is not
 * trustworthy, so no part of it is reported.
 *
 * A problem in ONE LINE drops that line and counts it. The count is returned and
 * the caller prints it, so a shortened list still cannot read as a complete one.
 *
 * This started out refusing the whole response on any bad line. Running the real
 * path killed that: a legitimate issuer account had 2 lines in 300 carrying
 * exponent-form balances, an over-strict pattern rejected them, and one bad line
 * erased 298 good ones. Refuse-all also hands anyone who can place an odd trust
 * line a denial of service against that account's whole report. Dropping loudly
 * is honest and does not amplify.
 */
export function validateAccountLinesResponse(
  raw: unknown,
  expectedAddress: string,
): Result<AccountLines> {
  const envelope = openEnvelope(raw);
  if (!envelope.ok) return envelope;
  const result = envelope.value;

  const account = own(result, "account");
  if (account !== undefined && account !== expectedAddress) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node returned trust lines for a different account than the one requested, so they were refused.",
    );
  }

  const rawLines = own(result, "lines");
  if (!Array.isArray(rawLines)) {
    return refuse(
      "RESPONSE_MALFORMED",
      "The XRPL node did not return a readable trust line list, so none are being reported. This is not the same as an account having no trust lines.",
    );
  }

  if (rawLines.length > BOUNDS.LINES_PER_PAGE * 4) {
    return refuse(
      "RESPONSE_TOO_LARGE",
      "The XRPL node returned more trust lines in one page than this plugin will accept, so the response was refused.",
    );
  }

  const lines: TrustLine[] = [];
  let droppedLines = 0;

  for (const line of rawLines) {
    if (!isPlainObject(line)) {
      droppedLines++;
      continue;
    }
    const peer = own(line, "account");
    const balance = own(line, "balance");
    const currency = own(line, "currency");
    const limit = own(line, "limit");

    // Every field must be readable on its own terms. A line failing any of
    // these is omitted and counted, never repaired and never defaulted.
    if (
      !isValidXrplAddress(peer) ||
      !isLedgerNumber(balance) ||
      !isLedgerNumber(limit) ||
      typeof currency !== "string" ||
      currency === "" ||
      currency.length > MAX_NUMERIC_CHARS
    ) {
      droppedLines++;
      continue;
    }

    lines.push({ account: peer, balance, currency, limit });
  }

  const ledgerIndex = readLedgerIndex(result);
  if (!ledgerIndex.ok) return ledgerIndex;

  const marker = own(result, "marker");
  const base = { lines, ledgerIndex: ledgerIndex.value, droppedLines };
  return ok(marker === undefined ? base : { ...base, marker });
}
