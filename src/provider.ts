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
import {
  ADDRESS_CANDIDATE_PATTERN,
  type HiddenAddressScan,
  scanHiddenAddresses,
  validateXrplAddress,
} from "./core/address.ts";
import { BOUNDS } from "./core/bounds.ts";
import { XRPL_NODE_URL } from "./core/node-url.ts";
import { checkRateLimit, pruneWindow } from "./core/ratelimit.ts";
import { type HiddenAddressNotice, renderAccountReport, renderRefusal } from "./core/render.ts";
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
  skippedDigest,
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
 * `otherAddresses` is the LIST of further addresses the message held that this
 * lookup never used. A refusal carries it for the same reason the report does:
 * "that address was refused" in a message naming three reads as an answer about
 * all three, and D6 is exactly that omission going unspoken.
 *
 * The LIST rather than a count, because F6 measured what a count alone buys. A
 * refusal message is the only text the model gets when a lookup fails, so it is
 * report content, and it is the content with no successful report beside it to
 * contradict a guess.
 *
 * THE ROOM IS MEASURED, not assumed. This path applied no slice at all and was
 * held inside MAX_RENDERED_CHARS by arithmetic over two constants and a test:
 * worst case 1,229 of 4,000, and the smallest MAX_ECHOED_ADDRESSES that busts it
 * is seventeen. The notice renderer is handed what is actually left after the
 * refusal message, so raising a cap can cost names, which are counted, and can
 * never cost the bound.
 */
function speak(
  r: Refusal,
  otherAddresses: readonly unknown[],
  hidden: HiddenAddressScan,
  cache: CacheState,
): SpokenResult {
  // Every rendering decision lives in src/core/render.ts, including the size
  // bound and the printable-only property of the head. This file used to build
  // the head by interpolation and apply no slice at all, which is how
  // `error.name` from a hostile Error subclass put 200,000 characters and two
  // invisible ones straight into ProviderResult.text. A decision made here is a
  // decision the suite reaches only through the provider; made there, it is
  // exported and can be handed the hostile input directly.
  const notice: HiddenAddressNotice = { hidden: hidden.count, capped: hidden.capped };
  return {
    text: renderRefusal(r.message, otherAddresses, notice),
    values: { xrplLookup: "refused", xrplRefusalCode: r.code },
    data: {
      ok: false,
      code: r.code,
      xrplCache: cache,
      xrplHiddenAddresses: hidden.count,
      xrplAddressChecksCapped: hidden.capped,
    },
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
 * F8. The message named something address-shaped and NOTHING could be read.
 *
 * The message is deliberately free of anything taken FROM the message. The runs
 * carry attacker-chosen invisible characters and never leave the scanner, so
 * there is nothing here that could quote one.
 */
/**
 * The scan result the outer catch reports, and the only one it can support.
 *
 * run() can throw before it has read the message at all, so this branch knows
 * neither how many addresses were hidden nor whether the cap bit. Zero and
 * false are the values that state nothing. Do not "fix" this into reporting a
 * count nothing measured.
 */
const NOTHING_SCANNED: HiddenAddressScan = { count: 0, capped: false };

/**
 * The error's name, or a fixed string, and it CANNOT THROW.
 *
 * `name` is an ordinary property on an Error instance, so a subclass may define
 * it as a getter, and a getter may throw. MEASURED against the version that
 * read it inline: `class HostileName extends Error { get name() { throw ... } }`
 * made provider.get REJECT from inside the catch that exists to stop exactly
 * that, and on this runtime a rejected provider is erased entirely. The last
 * line of defence was the line that failed.
 *
 * Nothing else in that branch can throw: refuse() trims a string literal, and
 * renderRefusal defends its own inputs and takes only a string and two
 * constants from here.
 */
function errorName(error: unknown): string {
  try {
    if (!(error instanceof Error)) return "unknown error";
    const name: unknown = error.name;
    return typeof name === "string" ? name : "unknown error";
  } catch {
    return "unknown error";
  }
}

const NO_READABLE_ADDRESS = refuse(
  "NO_READABLE_ADDRESS",
  "No XRPL address could be read from that message. It held address-shaped characters interrupted by invisible or formatting characters, so nothing was looked up and no ledger data was retrieved. The counts below say what this plugin found.",
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

    // F8. The SECOND scanner, and it exists because the first one is ASCII-only.
    // One zero-width space inside an address makes the address invisible to
    // ADDRESS_CANDIDATE_PATTERN, so the message named an entity that produced no
    // candidate, no skipped entry, and therefore no line of any kind. MEASURED:
    // a message holding only such a run returned silent(), text.length 0, and on
    // this runtime that contributes zero characters to the prompt.
    //
    // A NUMBER, never the runs. They carry attacker-chosen invisible characters
    // and nothing downstream can print what it was never given.
    //
    // The raw candidate list goes IN so the scan can exclude an account the
    // ordinary path is already reporting. MEASURED without that exclusion:
    // `compare <A> and <A carrying a zero-width space>` printed `address: A`
    // with a real balance AND said an address hidden by invisible characters
    // was never looked up and no balance may be stated for it. One report,
    // both claims, one account.
    const hidden = scanHiddenAddresses(text, candidates);

    if ((!candidates || candidates.length === 0) && hidden.count === 0 && !hidden.capped) {
      return silent();
    }

    const first = candidates?.[0];
    // Nothing readable, but the message held at least one run this plugin could
    // not read. A refusal, and it SPEAKS: no network call, no rate-limit charge,
    // no cache. Nothing is charged until every check has passed.
    //
    // The lookup target is unchanged everywhere else on purpose. Refusing the
    // whole turn whenever a poisoned run is present would let one pasted
    // zero-width space silence every XRPL lookup at zero attacker cost, so the
    // substitution hazard is closed by SPEECH rather than by blocking.
    //
    // The null clause is for the TYPE CHECKER and nothing else: at run time
    // `first === undefined` already covers it, and it is written out rather
    // than coerced away because `candidates ?? []` is the fallback shape rule 7
    // bans and checks/failopen_lint.ts fails the build on.
    if (candidates === null || first === undefined) {
      return speak(NO_READABLE_ADDRESS, [], hidden, "not-cacheable");
    }

    // D6, the one place X-006 recorded this package breaking its own rule. Only
    // the FIRST address is ever looked up and the rest were dropped in silence.
    //
    // DISTINCT strings, so the same address written twice is not reported as a
    // second account: overstating an omission is the same class of inaccuracy
    // as hiding one, in a report whose only job is to be accurate.
    //
    // The LIST, not its size. What is safe to NAME is decided in one place, by
    // src/core/render.ts, which runs the checksum: a candidate that fails it is
    // counted and never quoted, because the base58 class spells English.
    //
    // Two things are still decided HERE, and each has one job left:
    //
    // `c !== first` is the REFUSAL path's only protection. On the report path
    // the renderer removes the address it is reporting on by itself, but a
    // refusal has no subject to hand it, so a message "BAD ... A ... BAD" would
    // otherwise count and describe the very address the refusal is about.
    //
    // `new Set` is what makes the CACHE KEY canonical. The renderer de-duplicates
    // for what it prints, so "A ... B ... B" and "A ... B" render identically;
    // without the dedupe here their digests differ, the two turns land on
    // different entries, and a cache that serves identical reports twice has
    // quietly stopped working.
    const skipped = [...new Set(candidates.filter((c) => c !== first))];

    // F9. What a REFUSAL is handed, and it is deliberately NOT `skipped`.
    //
    // MEASURED on `compare A and B and C` with the node answering an error:
    // B and C were each named with "no balance may be stated for it" and A,
    // the account the user actually asked about, got no name, no line and no
    // guard. That is F6's own lesson inverted and pointed at the one account
    // that matters most. A refusal describes NOTHING, so there is no subject to
    // exclude and every distinct candidate belongs in the list, A included.
    // The renderer prints only what passes the checksum, so an unvalidated
    // first candidate is still counted and never quoted.
    const allNamed = [...new Set(candidates)];

    const address = validateXrplAddress(first);
    // Not cached, and the cache is not even consulted yet. Nothing read the
    // ledger, so there is nothing a later call could legitimately replay, and an
    // unvalidated string is not a partition this code is willing to key on.
    if (!address.ok) return speak(address, allNamed, hidden, "not-cacheable");

    // ONE ATOMIC STEP, from here to the stamps update below. Nothing in it may
    // suspend. The limiter's read-then-write is only safe because no call can
    // interleave between them, and inserting the cache read into that window
    // must not be what breaks it.
    const now = deps.now();
    const key = turnCacheKey({
      agentId: runtime?.agentId,
      messageId: message?.id,
      address: address.value,
      // The DIGEST of the same array the names are rendered from. ONE source: a
      // count beside it is a second number that can disagree, and disagreeing is
      // exactly what it did. Under the count form, one message.id with turn 1
      // saying "A and B" and turn 2 saying "A and C" was ONE key, so turn 2 was
      // served a report NAMING B while C went unmentioned.
      skipped: skippedDigest(skipped, hidden.count),
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
    if (!limit.ok) return speak(limit, allNamed, hidden, cacheState);
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
    if (!rawInfo.ok) return remember(speak(rawInfo, allNamed, hidden, cacheState));

    const info = validateAccountInfoResponse(rawInfo.value, address.value);
    if (!info.ok) return remember(speak(info, allNamed, hidden, cacheState));

    const linesResult = await fetchLines(address.value, budget);
    if ("ok" in linesResult && linesResult.ok === false) {
      return remember(speak(linesResult, allNamed, hidden, cacheState));
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
        otherAddressCandidates: skipped,
        hiddenAddresses: hidden.count,
        addressChecksCapped: hidden.capped,
      }),
      values: {
        xrplLookup: "ok",
        xrplAddress: account.address,
        xrplBalanceDrops: account.balanceDrops,
      },
      data: {
        ok: true,
        attempted: true,
        ledgerIndex: account.ledgerIndex,
        xrplCache: cacheState,
        xrplHiddenAddresses: hidden.count,
        xrplAddressChecksCapped: hidden.capped,
      },
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
        // NO further addresses, because nothing here knows: run() can throw
        // before it has read the message at all, and one of the tests below
        // makes content.text itself throw. Saying nothing about other addresses
        // is the only claim this branch can support, and an empty list renders
        // exactly as the old zero did, which is nothing.
        //
        // ZERO unreadable runs, for exactly that reason and not for a different
        // one. This branch may never have seen the message text, so it cannot
        // say a run was there and cannot say one was not. Zero is the value that
        // states nothing, which is the only claim available. Do not "fix" this
        // into reporting a count nothing measured.
        //
        // The cache is neither read nor written here for the same reason. This
        // branch does not know the message, the address or the skipped count, so
        // it cannot build a key that means anything.
        return speak(
          refuse(
            "INTERNAL_ERROR",
            `The XRPL lookup failed unexpectedly and no ledger data was retrieved (${errorName(
              error,
            )}).`,
          ),
          [],
          NOTHING_SCANNED,
          "not-cacheable",
        );
      }
    },
  };
}

/** The instance the plugin registers. */
export const xrplAccountProvider: Provider = createXrplProvider();
