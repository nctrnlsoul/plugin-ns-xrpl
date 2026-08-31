// The contract that the item 0 probe forced, and the reason it is not the
// obvious one.
//
// MEASURED against @elizaos/core 2.0.3-beta.7 by running AgentRuntime, not by
// reading its types (runtime.ts lines 3794-3865, 3932-3945):
//
//   - a provider that THROWS is caught, logged, and replaced with
//     {text:"",values:{},data:{}}. composeState resolves normally.
//   - a provider that returns undefined, {}, or {text:null} produces the same.
//   - a provider that HANGS is abandoned after COMPOSE_STATE_PROVIDER_TIMEOUT_MS
//     = 30_000 and replaced with the same empty result. Measured at 30,027ms.
//   - composeState then builds the prompt from provider texts that are non-empty
//     after trim. Every failed provider is FILTERED OUT of the string the model
//     reads. Zero characters survive: no error, no marker, nothing.
//
// So on this runtime `throw` is not fail-closed, it is fail-open. A refusal
// expressed as an exception becomes silence, and silence is indistinguishable
// from "this account has nothing worth reporting". The model then answers the
// user's question from its own priors.
//
// Hence the contract: the provider NEVER throws, and any attempted lookup that
// does not succeed returns an explicit, present, non-empty refusal string.
// A BLOCK has to be SPOKEN.
//
// Written before src/provider.ts exists.

import { describe, expect, it, vi } from "vitest";
import { createXrplProvider } from "../provider.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

const msg = (text: string) => ({ content: { text } }) as never;
const rt = {} as never;

/** A fetch that always answers with the given body at HTTP 200. */
const fetchReturning = (body: unknown) =>
  vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }));

const okAccountInfo = {
  result: {
    account_data: {
      Account: ADDR,
      Balance: "56774133566",
      OwnerCount: 0,
      Sequence: 4,
      LedgerEntryType: "AccountRoot",
    },
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

describe("the provider never throws, whatever happens underneath", () => {
  const disasters: Array<[string, () => unknown]> = [
    [
      "fetch rejects",
      () =>
        vi.fn(async () => {
          throw new Error("ECONNREFUSED");
        }),
    ],
    ["fetch returns a non-Response", () => vi.fn(async () => 42 as never)],
    [
      "body is not JSON",
      () => vi.fn(async () => new Response("<html>502</html>", { status: 200 })),
    ],
    ["body is empty", () => vi.fn(async () => new Response("", { status: 200 }))],
    ["HTTP 500", () => vi.fn(async () => new Response("{}", { status: 500 }))],
    ["HTTP 429", () => vi.fn(async () => new Response("{}", { status: 429 }))],
    ["body is null", () => fetchReturning(null)],
    ["body is an array", () => fetchReturning([1, 2, 3])],
    [
      "result.status is error",
      () => fetchReturning({ result: { status: "error", error: "actNotFound" } }),
    ],
    [
      "Balance missing",
      () =>
        fetchReturning({
          result: { account_data: { Account: ADDR }, validated: true, status: "success" },
        }),
    ],
    [
      "fetch hangs then aborts",
      () =>
        vi.fn(async (_u: unknown, init?: { signal?: AbortSignal }) => {
          return await new Promise<Response>((_res, rej) => {
            init?.signal?.addEventListener("abort", () => rej(new Error("aborted")));
          });
        }),
    ],
  ];

  for (const [name, makeFetch] of disasters) {
    it(`${name}: resolves with a SPOKEN refusal instead of throwing`, async () => {
      // Short timeout so the abort path is exercised in milliseconds rather
      // than by waiting out the production value. The production constant is
      // asserted separately below.
      const provider = createXrplProvider({ fetchImpl: makeFetch() as never, timeoutMs: 50 });
      let threw = false;
      let result: { text?: string } | undefined;
      try {
        result = await provider.get(rt, msg(`what is the balance of ${ADDR}`), undefined as never);
      } catch {
        threw = true;
      }
      expect(threw, "the provider must never throw: the runtime swallows it").toBe(false);
      expect(result).toBeDefined();
      // The whole point. Non-empty AFTER trim, because composeState filters on
      // text.trim() !== "".
      expect(
        (result?.text ?? "").trim().length,
        "an empty refusal is an invisible refusal",
      ).toBeGreaterThan(0);
    });
  }
});

describe("the outer catch is real, not decoration", () => {
  // Found by checks/mutations.ts, which is the whole reason that harness
  // exists. Making the provider's outer catch rethrow left the entire suite
  // green: every failure above is returned as a VALUE by the inner code, so
  // nothing ever entered the catch. The guard was untested and would have
  // shipped that way.
  //
  // These force a throw from inside run() itself, on paths that sit outside
  // every inner try.

  it("survives a clock that throws", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchReturning(okAccountInfo) as never,
      now: () => {
        throw new Error("CLOCK_SENTINEL");
      },
    });
    let threw = false;
    let result: { text?: string } | undefined;
    try {
      result = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    expect((result?.text ?? "").trim().length).toBeGreaterThan(0);
    // The internal error must not leak its detail into the model's context.
    expect(result?.text ?? "").not.toContain("CLOCK_SENTINEL");
  });

  it("survives a message whose text getter throws", async () => {
    const hostile = {
      content: {
        get text(): string {
          throw new Error("GETTER_SENTINEL");
        },
      },
    };
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    let threw = false;
    let result: { text?: string } | undefined;
    try {
      result = await provider.get(rt, hostile as never, undefined as never);
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    expect((result?.text ?? "").trim().length).toBeGreaterThan(0);
    expect(result?.text ?? "").not.toContain("GETTER_SENTINEL");
  });

  it("survives a match() that throws", async () => {
    // A String subclass is not exotic: anything that reaches content.text is
    // outside this package's control.
    const hostile = {
      content: {
        text: Object.assign(Object.create(String.prototype), {
          match: () => {
            throw new Error("MATCH_SENTINEL");
          },
          toString: () => "x",
        }),
      },
    };
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const result = await provider.get(rt, hostile as never, undefined as never);
    expect(result).toBeDefined();
    expect(result.text ?? "").not.toContain("MATCH_SENTINEL");
  });
});

describe("refusals are legible, not just non-empty", () => {
  it("a node failure says the lookup failed and does not imply a balance", async () => {
    const provider = createXrplProvider({
      fetchImpl: vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    const text = r.text ?? "";
    expect(text.toLowerCase()).toMatch(/could not|unable|failed|refus/);
    // It must not look like an answer.
    expect(text).not.toMatch(/\b0 XRP\b/);
    expect(text).not.toMatch(/holds 0\b/);
  });

  it("a not-found account is reported as not found, never as zero", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchReturning({
        result: { status: "error", error: "actNotFound", error_message: "Account not found." },
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    const text = (r.text ?? "").toLowerCase();
    expect(text).toContain("not");
    expect(text).not.toMatch(/\b0 xrp\b/);
  });

  it("a malformed address is refused without any network call at all", async () => {
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    // Valid charset and length, bad checksum. rippled itself called this
    // actMalformed on 2026-08-31, so it is a real bad address rather than an
    // invented one that would not even reach the validator.
    const r = await provider.get(
      rt,
      msg("balance of rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk"),
      undefined as never,
    );
    expect(fetchImpl, "a bad address must never reach the network").not.toHaveBeenCalled();
    expect((r.text ?? "").trim().length).toBeGreaterThan(0);
  });
});

describe("silence is permitted only when nothing was attempted", () => {
  it("returns empty text when the message contains no XRPL address", async () => {
    // This is the one legitimate empty result: not a failure, a non-event. If
    // the provider spoke on every unrelated message it would pollute every
    // prompt in the agent.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg("what is the weather like today"), undefined as never);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect((r.text ?? "").trim()).toBe("");
  });

  it("but speaks whenever an address was present and the lookup did not succeed", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchReturning({ result: { status: "error", error: "internal" } }) as never,
    });
    const r = await provider.get(rt, msg(`tell me about ${ADDR}`), undefined as never);
    expect((r.text ?? "").trim().length).toBeGreaterThan(0);
  });
});

describe("bounds are enforced at the provider edge (H-2)", () => {
  it("aborts the request rather than waiting on a hung node", async () => {
    // The runtime's own timeout is 30 seconds and it is silent. This one is
    // shorter and it speaks.
    const fetchImpl = vi.fn(async (_u: unknown, init?: { signal?: AbortSignal }) => {
      return await new Promise<Response>((_res, rej) => {
        init?.signal?.addEventListener("abort", () => rej(new Error("aborted")));
      });
    });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, timeoutMs: 50 });
    const started = Date.now();
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(Date.now() - started).toBeLessThan(2_000);
    expect((r.text ?? "").trim().length).toBeGreaterThan(0);
    expect((r.text ?? "").toLowerCase()).toMatch(/did not answer|abandon|timed out/);
    const init = fetchImpl.mock.calls[0]?.[1] as { signal?: AbortSignal } | undefined;
    expect(init?.signal, "every outbound request carries an abort signal").toBeDefined();
  });

  it("the SHIPPED timeout is below the runtime's own silent 30 second cutoff", async () => {
    // The test above proves the abort mechanism at 50ms. This proves the value
    // production actually uses is small enough to matter: if it were above
    // 30,000ms the runtime would abandon the provider first and the refusal
    // would never be spoken, which is the whole failure mode being avoided.
    const { BOUNDS } = await import("../core/bounds.ts");
    const RUNTIME_SILENT_CUTOFF_MS = 30_000; // measured, composeState, 2.0.3-beta.7

    expect(BOUNDS.REQUEST_TIMEOUT_MS).toBeGreaterThan(0);
    expect(BOUNDS.REQUEST_TIMEOUT_MS).toBeLessThan(RUNTIME_SILENT_CUTOFF_MS);

    // The number that actually protects the guarantee. An earlier version of
    // this test asserted REQUEST_TIMEOUT_MS * 2, which is the wrong quantity:
    // one lookup issues one account_info plus up to
    // MAX_PAGINATION_FOLLOWUPS + 1 account_lines pages, and at 8,000ms each
    // that worst case is 32,000ms, past the cutoff. The per-call budget is what
    // has to be under it.
    const worstCaseRequests = 1 + (BOUNDS.MAX_PAGINATION_FOLLOWUPS + 1);
    expect(worstCaseRequests).toBeGreaterThan(2);
    expect(BOUNDS.TOTAL_LOOKUP_BUDGET_MS).toBeLessThan(RUNTIME_SILENT_CUTOFF_MS);
    // Real margin, not a single millisecond of it.
    expect(BOUNDS.TOTAL_LOOKUP_BUDGET_MS).toBeLessThanOrEqual(RUNTIME_SILENT_CUTOFF_MS - 5_000);
  });

  it("abandons the whole lookup at the total budget, not just each request", async () => {
    // Every request hangs. Without a shared budget this would run
    // worstCaseRequests x perRequestTimeout. With one, it stops at the budget.
    const fetchImpl = vi.fn(async (_u: unknown, init?: { signal?: AbortSignal }) => {
      return await new Promise<Response>((_res, rej) => {
        init?.signal?.addEventListener("abort", () => rej(new Error("aborted")));
      });
    });
    const provider = createXrplProvider({
      fetchImpl: fetchImpl as never,
      timeoutMs: 200,
      totalBudgetMs: 300,
    });
    const started = Date.now();
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(1_500);
    expect((r.text ?? "").trim().length).toBeGreaterThan(0);
  });

  it("caps the rendered result even when the node returns an enormous body", async () => {
    const huge = {
      result: {
        account: ADDR,
        lines: Array.from({ length: 20_000 }, () => ({
          account: "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS",
          balance: "1",
          currency: "USD",
          limit: "1",
        })),
        ledger_index: 1,
        validated: true,
        status: "success",
      },
    };
    // Dispatch on the JSON-RPC method in the request body. Matching on the URL
    // would match both calls, since the node URL itself contains an "x", and the
    // cap would then never be exercised.
    const fetchImpl = vi.fn(async (_u: unknown, init?: { body?: string }) => {
      const method = String(init?.body ?? "");
      const body = method.includes("account_lines") ? huge : okAccountInfo;
      return new Response(JSON.stringify(body), { status: 200 });
    });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    const { BOUNDS } = await import("../core/bounds.ts");
    expect((r.text ?? "").length).toBeLessThanOrEqual(BOUNDS.MAX_RENDERED_CHARS);
  });

  it("rate limits, and says so rather than going quiet", async () => {
    const provider = createXrplProvider({ fetchImpl: fetchReturning(okAccountInfo) as never });
    const { BOUNDS } = await import("../core/bounds.ts");
    let refusal = "";
    for (let i = 0; i < BOUNDS.RATE_LIMIT_MAX_REQUESTS + 3; i++) {
      const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
      if ((r.text ?? "").toLowerCase().includes("rate")) refusal = r.text ?? "";
    }
    expect(refusal, "the rate limiter must speak when it refuses").not.toBe("");
  });
});

describe("the factory is called with production inputs (kickoff step 8b)", () => {
  it("createXrplProvider() with no arguments builds a usable Provider", async () => {
    // Step 8b: a suite can be green, thorough, and never once construct the
    // object the module exists to produce.
    const provider = createXrplProvider();
    expect(provider).toBeDefined();
    expect(typeof provider.name).toBe("string");
    expect(provider.name.length).toBeGreaterThan(0);
    expect(typeof provider.get).toBe("function");
    expect(typeof provider.description).toBe("string");
  });

  it("the exported plugin registers that provider and no signing surface", async () => {
    const { xrplPlugin } = await import("../plugin.ts");
    expect(xrplPlugin.providers?.length).toBeGreaterThan(0);
    // Zero signing surface is definition-of-done item 3.
    expect(xrplPlugin.actions ?? []).toHaveLength(0);
    expect(JSON.stringify(xrplPlugin)).not.toMatch(/seed|privateKey|secret|sign|submit/i);
  });
});
