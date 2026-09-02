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

  /**
   * Lookups permitted per window. V-005.
   *
   * Per provider INSTANCE, which sounds narrower than it is: src/provider.ts
   * exports one instance at module level and the plugin registers that one, so
   * in practice this is one window per PROCESS. Every agent sharing the process
   * shares the budget, and a busy agent can spend a quiet agent's share of it.
   */
  RATE_LIMIT_MAX_REQUESTS: 10,

  RATE_LIMIT_WINDOW_MS: 60_000,

  /**
   * How long one turn's cached lookup stays servable.
   *
   * This is a MEMORY bound and not a freshness control. Freshness comes from the
   * KEY, which is scoped to a single message id, so a stale entry can only ever
   * be served inside the turn that produced it, and a turn is over in seconds.
   *
   * The floor of TOTAL_LOOKUP_BUDGET_MS is a MARGIN, not a derivation, and it
   * used to be a derivation. Saying which it is matters, because a constant
   * whose stated reason is stale is a constant nobody can safely change later.
   *
   * The old reason: the entry was stamped with the clock read BEFORE the network,
   * so a lookup that spent its whole budget wrote an entry already 20,000ms old,
   * and the TTL had to cover that. That reason is dead. The stamp is now taken at
   * WRITE time, so network time is not charged against the TTL at all, and
   * src/__tests__/provider-cache.test.ts pins exactly that.
   *
   * What the TTL actually has to cover now is the gap between the WRITE of the
   * first ask and the READ of the second, within one turn. Between those two the
   * host runs a stage-1 model generation and its own bookkeeping. That interval
   * belongs to the model and the host, nothing shipped here bounds it, and
   * nothing here can measure it. So this number is CHOSEN, not computed.
   *
   * TOTAL_LOOKUP_BUDGET_MS is the unit only because it is the largest interval
   * this package does control, which makes "at least one whole lookup" a floor
   * that can be stated and tested. It is not a claim that the budget is the
   * interval being covered.
   *
   * A margin is acceptable here and would not be for a security bound, because
   * expiry is fail-SAFE in both directions: too short degrades to the doubled
   * lookup this cache exists to remove, never to a wrong answer, and correctness
   * comes from the key being scoped to one message id rather than from the TTL.
   */
  TURN_CACHE_TTL_MS: 30_000,

  /**
   * Entries retained. The worst case is arithmetic rather than a guess: 64
   * entries times MAX_RENDERED_CHARS (4,000) is roughly 256 KB. Per PROCESS, not
   * per agent, for the same singleton reason the rate limit window is.
   */
  TURN_CACHE_MAX_ENTRIES: 64,
} as const;

export type Bounds = typeof BOUNDS;
