// The ElizaOS surface. Thin, and it has exactly one job the core cannot do:
// guarantee that a refusal is SPOKEN, and spoken IN TIME.
//
// Why that is the job, measured against @elizaos/core 2.0.3-beta.7 by running
// AgentRuntime rather than reading its types (runtime.ts 3794-3865, 3932-3945):
//
//   throw            -> caught, logged, replaced with {text:"",values:{},data:{}}
//   return undefined -> same
//   return {}        -> same
//   {text:null}      -> same
//   hang             -> abandoned at 30,000ms, same. Measured at 30,027ms.
//
// composeState then builds the prompt only from provider texts that are
// non-empty after trim, so every one of those contributes ZERO characters. No
// error, no marker, nothing. The model answers the user's XRPL question from its
// own priors and nothing in the prompt says the lookup failed.
//
// So on this runtime `throw` is fail-OPEN. Rule 10 still holds, but BLOCK has to
// be a value that speaks, not an exception.
//
// The "in time" half is easy to miss. A refusal produced after 30,000ms is
// discarded by the runtime just as completely as a thrown one, so the total wall
// clock of a lookup is a security bound and not a performance preference. Hence
// the shared budget below.
//
// WHERE THE REPORT LANDS, which is a separate matter from the silence above.
// ElizaOS answers in two stages. Stage 1 (RESPONSE_HANDLER) builds its prompt
// with composeResponseState, from a fixed provider list plus whatever declares
// alwaysInResponseState; stage 2 (ACTION_PLANNER) is where an ordinary provider
// runs, and depending on what stage 1 produces the runtime may or may not go on
// to run that second stage.
//
// `alwaysInResponseState` is the only flag that puts a provider into the stage-1
// prompt, which is why the object returned below carries it. What it guarantees
// is narrow, and is stated narrowly on purpose: the report is composed into the
// stage-1 response state whichever contexts the turn selects. Measured against
// the real runtime in src/__tests__/runtime-integration.test.ts, with the flag
// off and nothing else changed, the report is absent from that prompt and no
// lookup runs during stage 1. That is the claim. It is not a claim that the
// provider would otherwise go unasked, nor one about what the model would answer.
//
// `private` must never be set beside the flag: alwaysOnResponseStateProviderNames
// requires `alwaysInResponseState && name && !provider.private`, so `private`
// cancels the flag in silence.

import type { IAgentRuntime, Memory, Provider, ProviderResult, State } from "@elizaos/core";
import { ADDRESS_CANDIDATE_PATTERN, validateXrplAddress } from "./core/address.ts";
import { BOUNDS } from "./core/bounds.ts";
import { XRPL_NODE_URL } from "./core/node-url.ts";
import { checkRateLimit, pruneWindow } from "./core/ratelimit.ts";
import { renderAccountReport, renderOtherAddressesNotice } from "./core/render.ts";
import {
  type AccountInfo,
  type TrustLine,
  validateAccountInfoResponse,
  validateAccountLinesResponse,
} from "./core/response.ts";
import type { Refusal } from "./core/result.ts";
import { refuse } from "./core/result.ts";
import {
  type CachedScalar,
  createTurnCache,
  readTurnCache,
  turnCacheKey,
  writeTurnCache,
} from "./core/turncache.ts";
import { type FetchLike, rpcCall } from "./transport/client.ts";

export interface XrplProviderDeps {
  readonly fetchImpl: FetchLike;
  readonly nodeUrl: string;
  readonly now: () => number;
  /**
   * Per-request network timeout. Also a test seam, so the abort path can be
   * exercised in milliseconds instead of by waiting out the production value.
   */
  readonly timeoutMs: number;
  /** Wall-clock budget for the whole lookup, across every request it makes. */
  readonly totalBudgetMs: number;
}

/**
 * What the turn cache did on this call.
 *
 * Reported on `data`, which never reaches the prompt, so it costs no tokens and
 * widens no injection surface. It exists so that a key builder that has quietly
 * stopped producing keys is VISIBLE, instead of the provider silently reverting
 * to the doubled lookup the cache was added to remove.
 */
type CacheState = "hit" | "miss" | "not-cacheable";

/**
 * A ProviderResult with all three fields present and every value a scalar.
 *
 * Declared rather than inferred because the turn cache stores exactly this shape
 * and hands it back. Rule 7 bans defaulting an absent value on a deciding path,
 * and a field that cannot be absent is a field nothing has to default.
 */
interface SpokenResult extends ProviderResult {
  readonly text: string;
  readonly values: Record<string, CachedScalar>;
  readonly data: Record<string, CachedScalar>;
}

/**
 * Turn a refusal into a ProviderResult the model will actually see.
 *
 * `otherAddresses` is how many further addresses the message held that this
 * lookup never used. A refusal carries it for the same reason the report does:
 * "that address was refused" in a message naming three reads as an answer about
 * all three, and D6 is exactly that omission going unspoken.
 */
function speak(r: Refusal, otherAddresses: number, cache: CacheState): SpokenResult {
  const others = renderOtherAddressesNotice(otherAddresses);
  return {
    text: `XRPL lookup refused. ${r.message}${others === "" ? "" : ` ${others}`}`,
    values: { xrplLookup: "refused", xrplRefusalCode: r.code },
    data: { ok: false, code: r.code, xrplCache: cache },
  };
}

/**
 * The one legitimate empty result: the message mentioned no XRPL address, so
 * nothing was attempted and there is nothing to report. Speaking on every
 * unrelated message would pollute every prompt in the agent.
 *
 * Silence is permitted only when no work was done. Any attempted lookup that
 * does not succeed speaks.
 *
 * A FUNCTION and not a shared constant. This is the path that runs on every
 * message the agent ever sees, so a single shared object is handed to every
 * consumer in the process, and one consumer writing to its `values` rewrites
 * what every later no-address turn returns. That is the same property the turn
 * cache goes to trouble to hold on its own reads.
 */
function silent(): SpokenResult {
  return { text: "", values: {}, data: { ok: true, attempted: false, xrplCache: "not-cacheable" } };
}

const BUDGET_SPENT = refuse(
  "NODE_TIMEOUT",
  "The XRPL lookup ran out of its time budget before it finished, so it was abandoned and no ledger data was retrieved.",
);

/**
 * Build the provider.
 *
 * The rate limiter's window and the turn cache's map both live in this closure,
 * one of each per provider INSTANCE. That reads narrower than it is: the export
 * at the bottom of this file is a module-level singleton and the plugin
 * registers that one, so in practice there is one window and one cache per
 * PROCESS, shared by every agent running in it.
 *
 * Only the STATE lives here. Every decision about it is an exported pure
 * function in src/core/, because a validator hidden inside a closure lands where
 * the suite cannot reach it, which src/core/response.ts and src/core/node-url.ts
 * both record as a defect this repo has already had.
 */
export function createXrplProvider(overrides: Partial<XrplProviderDeps> = {}): Provider {
  const deps: XrplProviderDeps = {
    fetchImpl: overrides.fetchImpl ?? (globalThis.fetch as unknown as FetchLike),
    nodeUrl: overrides.nodeUrl ?? XRPL_NODE_URL,
    now: overrides.now ?? (() => Date.now()),
    timeoutMs: overrides.timeoutMs ?? BOUNDS.REQUEST_TIMEOUT_MS,
    totalBudgetMs: overrides.totalBudgetMs ?? BOUNDS.TOTAL_LOOKUP_BUDGET_MS,
  };

  let stamps: number[] = [];
  const turnCache = createTurnCache();

  /** A deadline shared by every request in one lookup. */
  function makeBudget() {
    const deadline = Date.now() + deps.totalBudgetMs;
    return {
      /** Timeout for the next request: never more than the budget has left. */
      next: (): number => Math.min(deps.timeoutMs, deadline - Date.now()),
      spent: (): boolean => deadline - Date.now() <= 0,
    };
  }

  type Budget = ReturnType<typeof makeBudget>;

  /**
   * What one trust line lookup found, including WHICH LEDGER it found it on.
   *
   * The ledger index is carried rather than dropped because this function is the
   * only place that knows it, and the report is the only place it matters. Each
   * page is its own request against `validated`, so a multi-page list can
   * straddle two ledgers even when the account_info call agreed with page one.
   */
  interface LinesResult {
    lines: TrustLine[];
    moreAvailable: boolean;
    droppedLines: number;
    /** The ledger the LAST page came from, or null if no page was read. */
    ledgerIndex: number | null;
    ledgerIndexVaried: boolean;
  }

  async function fetchLines(address: string, budget: Budget): Promise<LinesResult | Refusal> {
    const lines: TrustLine[] = [];
    const ledgersSeen = new Set<number>();
    let droppedLines = 0;
    let ledgerIndex: number | null = null;
    let marker: unknown;

    // Bounded pagination. An account can hold thousands of trust lines and each
    // page is another response charged to whoever holds the model key.
    for (let page = 0; page <= BOUNDS.MAX_PAGINATION_FOLLOWUPS; page++) {
      if (budget.spent()) return BUDGET_SPENT;

      const params: Record<string, unknown> = {
        account: address,
        ledger_index: "validated",
        limit: BOUNDS.LINES_PER_PAGE,
      };
      if (marker !== undefined) params.marker = marker;

      const raw = await rpcCall("account_lines", params, {
        fetchImpl: deps.fetchImpl,
        nodeUrl: deps.nodeUrl,
        timeoutMs: budget.next(),
      });
      if (!raw.ok) return raw;

      const parsed = validateAccountLinesResponse(raw.value, address);
      if (!parsed.ok) return parsed;

      lines.push(...parsed.value.lines);
      droppedLines += parsed.value.droppedLines;
      ledgerIndex = parsed.value.ledgerIndex;
      ledgersSeen.add(parsed.value.ledgerIndex);
      marker = parsed.value.marker;
      if (marker === undefined) {
        return {
          lines,
          moreAvailable: false,
          droppedLines,
          ledgerIndex,
          ledgerIndexVaried: ledgersSeen.size > 1,
        };
      }
    }

    // Stopped at the bound with a marker outstanding: more exist and this plugin
    // will not chase them. Reported rather than hidden.
    return {
      lines,
      moreAvailable: true,
      droppedLines,
      ledgerIndex,
      ledgerIndexVaried: ledgersSeen.size > 1,
    };
  }

  async function run(runtime: IAgentRuntime, message: Memory): Promise<SpokenResult> {
    const text = typeof message?.content?.text === "string" ? message.content.text : "";

    // Find a candidate, then validate it properly. The pattern locates; it never
    // decides.
    const candidates = text.match(ADDRESS_CANDIDATE_PATTERN);
    if (!candidates || candidates.length === 0) return silent();

    const first = candidates[0];
    if (first === undefined) return silent();

    // D6, the one place X-006 recorded this package breaking its own rule. Only
    // the FIRST address is ever looked up and the rest were dropped in silence.
    //
    // DISTINCT strings, so the same address written twice is not reported as a
    // second account: overstating an omission is the same class of inaccuracy
    // as hiding one, in a report whose only job is to be accurate.
    //
    // NOT validated, because they were never looked at. "How many were skipped"
    // is a smaller claim than "how many were real", and it is the claim this
    // code can actually support.
    const skipped = new Set(candidates.filter((c) => c !== first)).size;

    const address = validateXrplAddress(first);
    // Not cached, and the cache is not even consulted yet. Nothing read the
    // ledger, so there is nothing a later call could legitimately replay, and an
    // unvalidated string is not a partition this code is willing to key on.
    if (!address.ok) return speak(address, skipped, "not-cacheable");

    // ONE ATOMIC STEP, from here to the stamps update below. Nothing in it may
    // suspend. The limiter's read-then-write is only safe because no call can
    // interleave between them, and inserting the cache read into that window
    // must not be what breaks it.
    const now = deps.now();
    const key = turnCacheKey({
      agentId: runtime?.agentId,
      messageId: message?.id,
      address: address.value,
      skipped,
      now,
    });
    const cacheState: CacheState = key === null ? "not-cacheable" : "miss";

    // A hit returns HERE, before the rate limiter. A turn that already paid for
    // its lookup must not be refused for asking about it a second time.
    const cached = readTurnCache(turnCache, key, now);
    if (cached !== null) {
      return {
        text: cached.text,
        values: { ...cached.values },
        data: { ...cached.data, xrplCache: "hit" },
      };
    }

    const limit = checkRateLimit(stamps, now);
    // NEVER stored. This message asserts a fact about now, that the limit "has
    // been reached", so replaying it after the window reopened would be a false
    // statement in report content, and a refusal message is the only text the
    // model gets when a lookup fails.
    if (!limit.ok) return speak(limit, skipped, cacheState);
    stamps = pruneWindow([...stamps, now], now);
    // END OF THE ATOMIC STEP.

    /**
     * Store what a NETWORK READ produced, and hand it straight back.
     *
     * The rule, stated once: the cache holds exactly what a network read
     * produced and nothing else. So the success path and every refusal returned
     * at or after the first rpcCall go through here, and ADDRESS_MALFORMED,
     * RATE_LIMITED and the outer catch's INTERNAL_ERROR do not.
     *
     * The clock is read AGAIN here, and `now` above is deliberately not reused.
     * `now` was read before the first request, so it is wrong twice over:
     *   - it charges the whole network time to the entry's TTL, so a lookup that
     *     spends its budget writes an entry that is already 20,000ms old.
     *   - it hands evictTurnCache a clock OLDER than entries other turns wrote
     *     while this one was in flight, and isFresh is two-sided, so those newer
     *     entries have a negative age. A slow turn completing would delete a
     *     live entry belonging to a different turn.
     *
     * deps.now(), never Date.now(), so both remain injectable and testable.
     */
    function remember(result: SpokenResult): SpokenResult {
      let writtenAt: number;
      try {
        writtenAt = deps.now();
      } catch {
        // A clock that throws is not a reason to discard a report that already
        // came back from the ledger. Not caching is this module's safe direction
        // everywhere else and it is the safe direction here: the next call does
        // the real work. Nothing about the report itself is in doubt.
        return result;
      }
      writeTurnCache(turnCache, key, result, writtenAt);
      return result;
    }

    const budget = makeBudget();

    const rawInfo = await rpcCall(
      "account_info",
      { account: address.value, ledger_index: "validated" },
      { fetchImpl: deps.fetchImpl, nodeUrl: deps.nodeUrl, timeoutMs: budget.next() },
    );
    if (!rawInfo.ok) return remember(speak(rawInfo, skipped, cacheState));

    const info = validateAccountInfoResponse(rawInfo.value, address.value);
    if (!info.ok) return remember(speak(info, skipped, cacheState));

    const linesResult = await fetchLines(address.value, budget);
    if ("ok" in linesResult && linesResult.ok === false) {
      return remember(speak(linesResult, skipped, cacheState));
    }
    const { lines, moreAvailable, droppedLines, ledgerIndex, ledgerIndexVaried } =
      linesResult as LinesResult;

    const account: AccountInfo = info.value;
    return remember({
      text: renderAccountReport({
        address: account.address,
        balanceDrops: account.balanceDrops,
        ledgerIndex: account.ledgerIndex,
        ownerCount: account.ownerCount,
        sequence: account.sequence,
        lines,
        truncatedLines: 0,
        moreAvailable,
        droppedLines,
        linesLedgerIndex: ledgerIndex,
        linesLedgerVaried: ledgerIndexVaried,
        otherAddressesNotLookedUp: skipped,
      }),
      values: {
        xrplLookup: "ok",
        xrplAddress: account.address,
        xrplBalanceDrops: account.balanceDrops,
      },
      data: { ok: true, attempted: true, ledgerIndex: account.ledgerIndex, xrplCache: cacheState },
    });
  }

  return {
    name: "XRPL_ACCOUNT",
    description:
      "Public XRPL ledger data (XRP balance and trust lines) for a classic address mentioned in the conversation. Read-only.",
    // Stage 1 builds its prompt from a fixed provider list plus whatever carries
    // this flag. With it, the report is composed into the stage-1 response state
    // whichever contexts the turn selects; without it, the report is absent from
    // that prompt and no lookup runs during stage 1.
    //
    // `private` is deliberately absent and must stay absent: the runtime cancels
    // this flag whenever `private` is truthy, and says nothing when it does.
    alwaysInResponseState: true,
    // DECLARATIVE, and said plainly because a comment that reads as a control is
    // the src/core/node-url.ts failure CLAUDE.md records: that file described a
    // private-range block it did not implement, and the description answered the
    // audit on the control's behalf.
    //
    // This is not a control. MEASURED against the pinned @elizaos/core
    // 2.0.3-beta.7: all 56 occurrences of `cacheStable` in that build are
    // declarations or action-metadata copies, and nothing reads
    // `provider.cacheStable` anywhere, so setting it changes no behaviour today
    // and deleting it would change none either. It is here so that a core which
    // does start reading it gets the right answer, which is that a point-in-time
    // reading of a ledger closing every four seconds is never stable enough for
    // a prompt cache. No test pins it, because there is no behaviour to pin.
    cacheStable: false,
    get: async (
      runtime: IAgentRuntime,
      message: Memory,
      _state?: State,
    ): Promise<ProviderResult> => {
      try {
        return await run(runtime, message);
      } catch (error) {
        // The last line of defence. Anything escaping above would otherwise be
        // swallowed by the runtime and become silence.
        //
        // Zero further addresses, because nothing here knows: run() can throw
        // before it has read the message at all, and one of the tests below
        // makes content.text itself throw. Saying nothing about other addresses
        // is the only claim this branch can support.
        //
        // The cache is neither read nor written here for the same reason. This
        // branch does not know the message, the address or the skipped count, so
        // it cannot build a key that means anything.
        return speak(
          refuse(
            "INTERNAL_ERROR",
            `The XRPL lookup failed unexpectedly and no ledger data was retrieved (${
              error instanceof Error ? error.name : "unknown error"
            }).`,
          ),
          0,
          "not-cacheable",
        );
      }
    },
  };
}

/** The instance the plugin registers. */
export const xrplAccountProvider: Provider = createXrplProvider();
