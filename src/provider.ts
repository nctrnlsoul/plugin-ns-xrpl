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
 * Turn a refusal into a ProviderResult the model will actually see.
 *
 * `otherAddresses` is how many further addresses the message held that this
 * lookup never used. A refusal carries it for the same reason the report does:
 * "that address was refused" in a message naming three reads as an answer about
 * all three, and D6 is exactly that omission going unspoken.
 */
function speak(r: Refusal, otherAddresses: number): ProviderResult {
  const others = renderOtherAddressesNotice(otherAddresses);
  return {
    text: `XRPL lookup refused. ${r.message}${others === "" ? "" : ` ${others}`}`,
    values: { xrplLookup: "refused", xrplRefusalCode: r.code },
    data: { ok: false, code: r.code },
  };
}

/**
 * The one legitimate empty result: the message mentioned no XRPL address, so
 * nothing was attempted and there is nothing to report. Speaking on every
 * unrelated message would pollute every prompt in the agent.
 *
 * Silence is permitted only when no work was done. Any attempted lookup that
 * does not succeed speaks.
 */
const SILENT: ProviderResult = { text: "", values: {}, data: { ok: true, attempted: false } };

const BUDGET_SPENT = refuse(
  "NODE_TIMEOUT",
  "The XRPL lookup ran out of its time budget before it finished, so it was abandoned and no ledger data was retrieved.",
);

/**
 * Build the provider.
 *
 * Rate limiter state lives in this closure, one window per provider instance.
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

  async function run(message: Memory): Promise<ProviderResult> {
    const text = typeof message?.content?.text === "string" ? message.content.text : "";

    // Find a candidate, then validate it properly. The pattern locates; it never
    // decides.
    const candidates = text.match(ADDRESS_CANDIDATE_PATTERN);
    if (!candidates || candidates.length === 0) return SILENT;

    const first = candidates[0];
    if (first === undefined) return SILENT;

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
    if (!address.ok) return speak(address, skipped);

    const now = deps.now();
    const limit = checkRateLimit(stamps, now);
    if (!limit.ok) return speak(limit, skipped);
    stamps = pruneWindow([...stamps, now], now);

    const budget = makeBudget();

    const rawInfo = await rpcCall(
      "account_info",
      { account: address.value, ledger_index: "validated" },
      { fetchImpl: deps.fetchImpl, nodeUrl: deps.nodeUrl, timeoutMs: budget.next() },
    );
    if (!rawInfo.ok) return speak(rawInfo, skipped);

    const info = validateAccountInfoResponse(rawInfo.value, address.value);
    if (!info.ok) return speak(info, skipped);

    const linesResult = await fetchLines(address.value, budget);
    if ("ok" in linesResult && linesResult.ok === false) return speak(linesResult, skipped);
    const { lines, moreAvailable, droppedLines, ledgerIndex, ledgerIndexVaried } =
      linesResult as LinesResult;

    const account: AccountInfo = info.value;
    return {
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
      data: { ok: true, attempted: true, ledgerIndex: account.ledgerIndex },
    };
  }

  return {
    name: "XRPL_ACCOUNT",
    description:
      "Public XRPL ledger data (XRP balance and trust lines) for a classic address mentioned in the conversation. Read-only.",
    get: async (
      _runtime: IAgentRuntime,
      message: Memory,
      _state?: State,
    ): Promise<ProviderResult> => {
      try {
        return await run(message);
      } catch (error) {
        // The last line of defence. Anything escaping above would otherwise be
        // swallowed by the runtime and become silence.
        //
        // Zero further addresses, because nothing here knows: run() can throw
        // before it has read the message at all, and one of the tests below
        // makes content.text itself throw. Saying nothing about other addresses
        // is the only claim this branch can support.
        return speak(
          refuse(
            "INTERNAL_ERROR",
            `The XRPL lookup failed unexpectedly and no ledger data was retrieved (${
              error instanceof Error ? error.name : "unknown error"
            }).`,
          ),
          0,
        );
      }
    },
  };
}

/** The instance the plugin registers. */
export const xrplAccountProvider: Provider = createXrplProvider();
