// The one shape every decision in this package returns.
//
// It is a value, never an exception, and that is not a style preference. The
// ElizaOS runtime catches anything a provider throws and replaces it with an
// empty result, which composeState then filters out of the prompt entirely
// (measured against 2.0.3-beta.7, see src/__tests__/provider-contract.test.ts).
// So on this runtime a thrown refusal is a silent one, and silence reads to the
// model as "nothing to report" rather than "this failed".
//
// A refusal therefore has to be a value that carries a message, so the message
// can be spoken.

/** Why a lookup did not produce an answer. Every one of these is reportable. */
export type RefusalCode =
  | "ADDRESS_MALFORMED"
  // The message named something address-shaped and NOTHING could be read from
  // it, because invisible or formatting characters sit inside the run. A
  // separate code from ADDRESS_MALFORMED because the two are different facts:
  // that one refused a string it could read, this one read no string at all.
  | "NO_READABLE_ADDRESS"
  | "ACCOUNT_NOT_FOUND"
  | "NODE_UNREACHABLE"
  | "NODE_TIMEOUT"
  | "RESPONSE_MALFORMED"
  | "RESPONSE_TOO_LARGE"
  | "RATE_LIMITED"
  | "NODE_URL_NOT_ALLOWED"
  | "LEDGER_ERROR"
  | "INTERNAL_ERROR";

export interface Ok<T> {
  readonly ok: true;
  readonly value: T;
}

export interface Refusal {
  readonly ok: false;
  readonly code: RefusalCode;
  /** Always non-empty. An empty refusal is an invisible refusal. */
  readonly message: string;
}

export type Result<T> = Ok<T> | Refusal;

export function ok<T>(value: T): Ok<T> {
  return { ok: true, value };
}

/**
 * Build a refusal. The message is forced non-empty here rather than trusted at
 * each of the several dozen call sites, because one empty message is one
 * silently missing report.
 */
export function refuse(code: RefusalCode, message: string): Refusal {
  const text = typeof message === "string" ? message.trim() : "";
  return { ok: false, code, message: text === "" ? `Refused: ${code}.` : text };
}
