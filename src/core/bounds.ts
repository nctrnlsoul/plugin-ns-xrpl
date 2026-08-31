// Finding H-2: "a read that costs zero on-chain costs unbounded tokens
// off-chain". An XRPL read costs nothing in drops and lands in a model context
// that somebody pays for, and the address is supplied by whoever is talking to
// the agent.
//
// Every bound is a constant here rather than an argument threaded through the
// call sites, so that raising one is a visible edit to a file whose only job is
// to hold limits.
//
// MEASURED, and the reason these are not decorative: with no cap, a provider
// returning 2,000,000 characters put all 2,000,023 characters of it into
// state.text. The ElizaOS runtime caps nothing (probe, 2026-08-31).

export const BOUNDS = {
  /** Trust lines printed in one report. */
  MAX_TRUST_LINES_RENDERED: 25,

  /**
   * Hard ceiling on the whole rendered report. This is the number that actually
   * protects the token budget: per-field caps still permit an unbounded total.
   */
  MAX_RENDERED_CHARS: 4_000,

  /** Ceiling on any single ledger-sourced value. */
  MAX_FIELD_CHARS: 64,

  /**
   * Per-request network timeout. Deliberately far below the runtime's own
   * COMPOSE_STATE_PROVIDER_TIMEOUT_MS of 30,000ms, which was measured resolving
   * at 30,027ms and contributing silence. Failing here instead means the failure
   * gets spoken.
   */
  REQUEST_TIMEOUT_MS: 8_000,

  /**
   * Wall-clock budget for ONE provider call, across every request it makes.
   *
   * A per-request timeout alone is not enough and the live run proved it: one
   * account_info plus up to three account_lines pages is four requests, and
   * 4 x 8,000ms is 32,000ms, which is PAST the runtime's own silent 30,000ms
   * cutoff. In that window the runtime abandons the provider and substitutes an
   * empty result, so the carefully spoken refusal never reaches the prompt and
   * the whole design fails exactly where it was supposed to hold.
   *
   * This budget is the guarantee that a refusal always arrives in time to be
   * heard. Keep it well under 30,000ms.
   */
  TOTAL_LOOKUP_BUDGET_MS: 20_000,

  /** Ceiling on a response body before it is parsed. */
  MAX_RESPONSE_BYTES: 1_048_576,

  /** How many `marker` follow-ups the transport will chase. */
  MAX_PAGINATION_FOLLOWUPS: 2,

  /** Trust lines requested per page. */
  LINES_PER_PAGE: 100,

  /** Lookups permitted per window, per provider instance. V-005. */
  RATE_LIMIT_MAX_REQUESTS: 10,

  RATE_LIMIT_WINDOW_MS: 60_000,
} as const;

export type Bounds = typeof BOUNDS;
