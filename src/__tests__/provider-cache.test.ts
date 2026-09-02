// The in-turn cache, tested through the provider rather than through the module.
//
// Why it exists at all: the provider now carries alwaysInResponseState, which
// puts it in the stage-1 router prompt as well as the stage-2 planner's, so the
// runtime can ask it more than once per turn.
//
// PROVENANCE, because the number is stated as measured and this file does not
// produce it. "718ms then 571ms, two full network reads of identical data in one
// turn" was measured OUTSIDE this repo, on a running elizaOS agent with this
// provider registered. It is REPORTED, not reproduced: driving the pinned core's
// real message path yields ONE provider ask per turn every time, and no test in
// this tree constructs a two-ask turn.
//
// What IS verified, here and in runtime-integration.test.ts: the real runtime
// hands this provider the inbound message.id and a UUID agentId, so the key
// shape is right end to end, and every property below holds on a repeat ask
// however the runtime comes to make one.
//
// Every test below asserts the REASON, through data.xrplCache, rather than
// asserting that a lookup happened. "Two fetches did not happen" is also true of
// a lookup that failed before it reached the network, which is the shape rule 95
// names: a test is usually disabled by its setup, not its assertion.
//
// Written before the cache exists.

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { validateXrplAddress } from "../core/address.ts";
import { BOUNDS } from "../core/bounds.ts";
import { createXrplProvider } from "../provider.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const PEER = "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS";
/** Valid charset and length, bad checksum. rippled called this actMalformed. */
const BAD = "rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk";

const AGENT_A = randomUUID();
const AGENT_B = randomUUID();

const rt = (agentId?: string) => ({ agentId }) as never;
const msg = (text: string, id?: string) => ({ id, content: { text } }) as never;

const ACCOUNT_INFO_OK = {
  result: {
    account_data: {
      Account: ADDR,
      Balance: "56774133566",
      OwnerCount: 1,
      Sequence: 44196,
      LedgerEntryType: "AccountRoot",
    },
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

const LINES_OK = {
  result: {
    account: ADDR,
    lines: [{ account: PEER, balance: "10", currency: "USD", limit: "100" }],
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

function fetchByMethod(map: Record<string, unknown>) {
  return vi.fn(async (_url: unknown, init?: { body?: string }) => {
    const method = String(JSON.parse(String(init?.body ?? "{}")).method ?? "");
    const body = map[method];
    if (body === undefined) throw new Error(`unexpected method ${method}`);
    return new Response(JSON.stringify(body), { status: 200 });
  });
}

const okFetch = () => fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });

describe("the fixtures are what this file claims they are", () => {
  it("two valid distinct addresses and one that really fails its checksum", () => {
    expect(validateXrplAddress(ADDR).ok).toBe(true);
    expect(validateXrplAddress(PEER).ok).toBe(true);
    expect(validateXrplAddress(BAD).ok).toBe(false);
    expect(AGENT_A).not.toBe(AGENT_B);
  });
});

describe("one turn, one lookup", () => {
  it("the SECOND call performs ZERO fetches, and the window advanced by exactly ONE", async () => {
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);
    const turn = msg(`balance of ${ADDR}`, randomUUID());

    const first = await provider.get(runtime, turn, undefined as never);
    const afterFirst = fetchImpl.mock.calls.length;
    expect(afterFirst, "the first call must really have gone to the network").toBeGreaterThan(0);
    expect(first.data?.xrplCache).toBe("miss");

    const second = await provider.get(runtime, turn, undefined as never);
    expect(fetchImpl.mock.calls.length, "the second call must fetch nothing at all").toBe(
      afterFirst,
    );
    // "No fetch" alone would also pass if the second call had errored out early,
    // so prove it reached the state it claims: same report, served from cache.
    expect(second.data?.xrplCache).toBe("hit");
    expect(second.text).toBe(first.text);
    expect(second.text ?? "").toContain("56774133566");

    // And the window advanced by exactly one, proved from both sides. Nine more
    // distinct turns must ALL succeed, which is only true if the repeat above
    // consumed nothing; and the tenth must be refused, which is only true if the
    // first call consumed one.
    for (let i = 0; i < BOUNDS.RATE_LIMIT_MAX_REQUESTS - 1; i++) {
      const r = await provider.get(
        runtime,
        msg(`balance of ${ADDR}`, randomUUID()),
        undefined as never,
      );
      expect(r.values?.xrplRefusalCode, `turn ${i + 2} must not be refused`).toBeUndefined();
    }
    const overflow = await provider.get(
      runtime,
      msg(`balance of ${ADDR}`, randomUUID()),
      undefined as never,
    );
    expect(
      overflow.values?.xrplRefusalCode,
      "one lookup past the limit must be refused, or the first call spent nothing",
    ).toBe("RATE_LIMITED");
  });

  it("a different turn is a different lookup", async () => {
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);

    await provider.get(runtime, msg(`balance of ${ADDR}`, randomUUID()), undefined as never);
    const afterFirst = fetchImpl.mock.calls.length;
    const other = await provider.get(
      runtime,
      msg(`balance of ${ADDR}`, randomUUID()),
      undefined as never,
    );
    expect(other.data?.xrplCache).toBe("miss");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(afterFirst);
  });
});

describe("the key admits a turn, or the turn is not cached at all", () => {
  it("a message with NO id is looked up every time, and says so", async () => {
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);

    const one = await provider.get(runtime, msg(`balance of ${ADDR}`), undefined as never);
    const afterFirst = fetchImpl.mock.calls.length;
    const two = await provider.get(runtime, msg(`balance of ${ADDR}`), undefined as never);

    expect(one.data?.xrplCache).toBe("not-cacheable");
    expect(two.data?.xrplCache).toBe("not-cacheable");
    expect(
      fetchImpl.mock.calls.length,
      "an absent id must not become one shared partition",
    ).toBeGreaterThan(afterFirst);
  });

  it("a message id that is a string but not a UUID is not cacheable", async () => {
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);

    const one = await provider.get(
      runtime,
      msg(`balance of ${ADDR}`, "turn-1"),
      undefined as never,
    );
    const afterFirst = fetchImpl.mock.calls.length;
    const two = await provider.get(
      runtime,
      msg(`balance of ${ADDR}`, "turn-1"),
      undefined as never,
    );

    expect(one.data?.xrplCache).toBe("not-cacheable");
    expect(two.data?.xrplCache).toBe("not-cacheable");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(afterFirst);
  });

  it("a runtime with no agentId is not cacheable, even when the MESSAGE carries one", async () => {
    // The agent id is taken from the runtime deliberately. Memory.agentId is
    // optional and caller-shaped, and keying on it would let whoever wrote the
    // message choose which partition to read.
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const hostile = { id: randomUUID(), agentId: AGENT_A, content: { text: `balance of ${ADDR}` } };

    const one = await provider.get({} as never, hostile as never, undefined as never);
    expect(one.data?.xrplCache).toBe("not-cacheable");
    const afterFirst = fetchImpl.mock.calls.length;
    const two = await provider.get({} as never, hostile as never, undefined as never);
    expect(two.data?.xrplCache).toBe("not-cacheable");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(afterFirst);
  });

  it("two agents sharing one process never read each other's entry", async () => {
    // The provider is a module-level singleton, so one cache serves every agent
    // in the process. The agent id is what keeps those partitions apart.
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const turn = msg(`balance of ${ADDR}`, randomUUID());

    const a = await provider.get(rt(AGENT_A), turn, undefined as never);
    expect(a.data?.xrplCache).toBe("miss");
    const afterA = fetchImpl.mock.calls.length;

    const b = await provider.get(rt(AGENT_B), turn, undefined as never);
    expect(b.data?.xrplCache, "a second agent must do its own lookup").toBe("miss");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(afterA);
  });

  it("THRESHOLD: one further address changes the key, so the notice cannot be lost", async () => {
    // Invariant 10 through the cache. The two reports differ by exactly the
    // other_addresses_not_looked_up line, so a key that drops the count serves a
    // shortened report that reads as a complete one.
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);
    const id = randomUUID();

    const one = await provider.get(runtime, msg(`balance of ${ADDR}`, id), undefined as never);
    expect(one.text ?? "").not.toMatch(/other_addresses/i);

    const two = await provider.get(runtime, msg(`${ADDR} and ${PEER}`, id), undefined as never);
    expect(two.data?.xrplCache, "a different skipped count is a different key").toBe("miss");
    expect(two.text ?? "").toMatch(/^ {2}other_addresses_not_looked_up: 1\b/m);
  });
});

describe("what is cached is exactly what a network read produced", () => {
  it("a refusal from the NODE is cached, because a network read produced it", async () => {
    const fetchImpl = fetchByMethod({
      account_info: { result: { status: "error", error: "actNotFound" } },
    });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);
    const turn = msg(`balance of ${ADDR}`, randomUUID());

    const one = await provider.get(runtime, turn, undefined as never);
    expect(one.values?.xrplRefusalCode).toBe("ACCOUNT_NOT_FOUND");
    expect(one.data?.xrplCache).toBe("miss");
    const afterFirst = fetchImpl.mock.calls.length;
    expect(afterFirst).toBeGreaterThan(0);

    const two = await provider.get(runtime, turn, undefined as never);
    expect(two.values?.xrplRefusalCode).toBe("ACCOUNT_NOT_FOUND");
    expect(two.data?.xrplCache).toBe("hit");
    expect(two.text).toBe(one.text);
    expect(fetchImpl.mock.calls.length).toBe(afterFirst);
  });

  it("a MALFORMED ADDRESS is never cached: nothing read it, so there is nothing to replay", async () => {
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);
    const turn = msg(`look up ${BAD}`, randomUUID());

    const one = await provider.get(runtime, turn, undefined as never);
    expect(one.values?.xrplRefusalCode).toBe("ADDRESS_MALFORMED");
    expect(one.data?.xrplCache).toBe("not-cacheable");

    const two = await provider.get(runtime, turn, undefined as never);
    expect(two.data?.xrplCache, "the cache is never consulted before an address is validated").toBe(
      "not-cacheable",
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("a RATE LIMIT refusal is decided fresh every time, never replayed", async () => {
    // Its message asserts a fact about now: the limit "has been reached". Serving
    // that from a cache after the window reopened is a false statement in report
    // content, and a refusal message is the only text the model gets.
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);

    for (let i = 0; i < BOUNDS.RATE_LIMIT_MAX_REQUESTS; i++) {
      await provider.get(runtime, msg(`balance of ${ADDR}`, randomUUID()), undefined as never);
    }

    const turn = msg(`balance of ${ADDR}`, randomUUID());
    const one = await provider.get(runtime, turn, undefined as never);
    expect(one.values?.xrplRefusalCode, "the limiter must really be exhausted").toBe(
      "RATE_LIMITED",
    );
    expect(one.data?.xrplCache).toBe("miss");

    const two = await provider.get(runtime, turn, undefined as never);
    expect(two.values?.xrplRefusalCode).toBe("RATE_LIMITED");
    expect(two.data?.xrplCache, "a rate-limit refusal must never be stored").toBe("miss");
  });

  it("silence is not cached either: nothing was attempted", async () => {
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const r = await provider.get(
      rt(AGENT_A),
      msg("what is the weather like today", randomUUID()),
      undefined as never,
    );
    expect((r.text ?? "").trim()).toBe("");
    expect(r.data?.xrplCache).toBe("not-cacheable");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("the outer catch neither reads nor writes the cache", async () => {
    // It cannot: run() can throw before it has read the message at all, so this
    // branch does not know the message, the address, or the skipped count.
    const hostile = {
      id: randomUUID(),
      content: {
        get text(): string {
          throw new Error("GETTER_SENTINEL");
        },
      },
    };
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never, now: () => 1_000 });
    const r = await provider.get(rt(AGENT_A), hostile as never, undefined as never);
    expect(r.values?.xrplRefusalCode).toBe("INTERNAL_ERROR");
    expect(r.data?.xrplCache).toBe("not-cacheable");
    expect(r.text ?? "").not.toContain("GETTER_SENTINEL");
  });
});

describe("the cache is read before the rate limiter, and expires", () => {
  it("a HIT is served even when the rate limit is exhausted", async () => {
    const fetchImpl = okFetch();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });
    const runtime = rt(AGENT_A);
    const turn = msg(`balance of ${ADDR}`, randomUUID());

    const first = await provider.get(runtime, turn, undefined as never);
    expect(first.data?.xrplCache).toBe("miss");

    for (let i = 0; i < BOUNDS.RATE_LIMIT_MAX_REQUESTS - 1; i++) {
      await provider.get(runtime, msg(`balance of ${ADDR}`, randomUUID()), undefined as never);
    }
    const proof = await provider.get(
      runtime,
      msg(`balance of ${ADDR}`, randomUUID()),
      undefined as never,
    );
    expect(proof.values?.xrplRefusalCode, "the limiter must really be exhausted").toBe(
      "RATE_LIMITED",
    );

    const again = await provider.get(runtime, turn, undefined as never);
    expect(again.data?.xrplCache, "the cache is consulted BEFORE the limiter").toBe("hit");
    expect(again.text).toBe(first.text);
  });

  it("THRESHOLD: one millisecond past the TTL is looked up again", async () => {
    const fetchImpl = okFetch();
    let clock = 1_000;
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => clock });
    const runtime = rt(AGENT_A);
    const turn = msg(`balance of ${ADDR}`, randomUUID());

    await provider.get(runtime, turn, undefined as never);
    const afterFirst = fetchImpl.mock.calls.length;

    clock = 1_000 + BOUNDS.TURN_CACHE_TTL_MS;
    expect((await provider.get(runtime, turn, undefined as never)).data?.xrplCache).toBe("hit");

    clock = 1_001 + BOUNDS.TURN_CACHE_TTL_MS;
    const stale = await provider.get(runtime, turn, undefined as never);
    expect(stale.data?.xrplCache, "an expired entry must be a miss").toBe("miss");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(afterFirst);
  });

  it("nothing awaits between the clock read and the rate-limiter update", () => {
    // Atomicity, and it can only be checked here. Today checkRateLimit and the
    // stamps update cannot interleave with another call because nothing suspends
    // between them, and the cache read was inserted into that same window. One
    // suspension point restores the interleaving the limiter exists to prevent.
    const source = readFileSync(join(import.meta.dirname, "..", "provider.ts"), "utf8");
    const start = source.indexOf("const now = deps.now();");
    const end = source.indexOf("stamps = pruneWindow(");
    expect(start, "the clock read must be findable, or this test measures nothing").toBeGreaterThan(
      -1,
    );
    expect(end, "the stamps update must come after it").toBeGreaterThan(start);

    const code = source
      .slice(start, end)
      .split("\n")
      .filter((line) => !line.trim().startsWith("//"))
      .join("\n");
    expect(code, "the cache read and the rate limit must stay one atomic step").not.toMatch(
      /\bawait\b/,
    );
  });
});

// The clock the entry is STAMPED with, which is not the clock the turn started
// on. Found by a cold adversarial pass, and it is two defects in one line:
// network time charged to the TTL, and a sweep run with a clock older than
// entries other turns wrote while this one was in flight.
describe("the entry is stamped when it is WRITTEN, not before the network read", () => {
  /** A second valid classic address, so one turn can be held while another runs. */
  const SLOW = PEER;

  const infoFor = (account: string) => ({
    result: {
      account_data: {
        Account: account,
        Balance: "56774133566",
        OwnerCount: 1,
        Sequence: 44196,
        LedgerEntryType: "AccountRoot",
      },
      ledger_index: 106661700,
      validated: true,
      status: "success",
    },
  });

  const linesFor = (account: string) => ({
    result: { account, lines: [], ledger_index: 106661700, validated: true, status: "success" },
  });

  /** A fetch that holds every request naming `held` until the caller releases it. */
  function gatedFetch(held: string) {
    let open: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const fetchImpl = vi.fn(async (_url: unknown, init?: { body?: string }) => {
      const body = String(init?.body ?? "");
      const account = body.includes(held) ? held : ADDR;
      if (account === held) await gate;
      const method = String(JSON.parse(body === "" ? "{}" : body).method ?? "");
      const payload = method === "account_info" ? infoFor(account) : linesFor(account);
      return new Response(JSON.stringify(payload), { status: 200 });
    });
    return { fetchImpl, release: () => open() };
  }

  it("THRESHOLD: a late write does not evict the ONE newer entry a faster turn left", async () => {
    // isFresh is two-sided, so an entry stamped LATER than the sweeping clock
    // has a negative age and is deleted. Stamping with the pre-network clock
    // hands the sweep a clock from before the slow turn even started, and a slow
    // turn completing then deletes a live entry belonging to a different turn.
    let clock = 0;
    const { fetchImpl, release } = gatedFetch(SLOW);
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => clock });
    const runtime = rt(AGENT_A);
    const fastTurn = msg(`balance of ${ADDR}`, randomUUID());

    // Turn A starts at t=0 and is held inside fetch.
    const slow = provider.get(runtime, msg(`balance of ${SLOW}`, randomUUID()), undefined as never);

    // Turn B runs to completion at t=5,000 while A is still in flight.
    clock = 5_000;
    const b1 = await provider.get(runtime, fastTurn, undefined as never);
    expect(b1.data?.xrplCache, "setup: turn B must really have been cached").toBe("miss");

    // Turn A finishes at t=10,000, ten seconds after the clock it started on.
    clock = 10_000;
    release();
    await slow;

    const before = fetchImpl.mock.calls.length;
    const b2 = await provider.get(runtime, fastTurn, undefined as never);
    expect(b2.data?.xrplCache, "a slow turn completing must not delete a live entry").toBe("hit");
    expect(fetchImpl.mock.calls.length, "and must not force it to be fetched again").toBe(before);
  });

  it("the TTL runs from the WRITE, so network time is not charged against it", async () => {
    // A lookup may legitimately spend TOTAL_LOOKUP_BUDGET_MS. Stamped with the
    // clock from before that spend, the entry is already 20,000ms of a 30,000ms
    // TTL old at the moment it is written, and the second ask of the same turn
    // can miss on an entry that was written moments earlier.
    let clock = 0;
    const { fetchImpl, release } = gatedFetch(SLOW);
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => clock });
    const runtime = rt(AGENT_A);
    const turn = msg(`balance of ${SLOW}`, randomUUID());

    const inFlight = provider.get(runtime, turn, undefined as never);
    clock = BOUNDS.TURN_CACHE_TTL_MS; // the network took the entire TTL
    release();
    const first = await inFlight;
    expect(first.data?.xrplCache, "setup: the lookup reached the network").toBe("miss");

    const before = fetchImpl.mock.calls.length;
    clock = BOUNDS.TURN_CACHE_TTL_MS + 1; // ONE millisecond after the write
    const again = await provider.get(runtime, turn, undefined as never);
    expect(again.data?.xrplCache, "one millisecond after the WRITE is still fresh").toBe("hit");
    expect(fetchImpl.mock.calls.length).toBe(before);
  });

  it("a clock that throws at WRITE time does not discard the report it already has", async () => {
    // The write-time stamp is a SECOND call to deps.now(). A throw escaping
    // there would turn a lookup that succeeded against the ledger into an
    // INTERNAL_ERROR refusal, which is the cache failing the lookup. Not caching
    // is the safe direction; refusing is not.
    let reads = 0;
    const fetchImpl = okFetch();
    const provider = createXrplProvider({
      fetchImpl: fetchImpl as never,
      now: () => {
        reads += 1;
        if (reads > 1) throw new Error("WRITE_CLOCK_SENTINEL");
        return 1_000;
      },
    });

    const r = await provider.get(
      rt(AGENT_A),
      msg(`balance of ${ADDR}`, randomUUID()),
      undefined as never,
    );
    expect(reads, "setup: the write-time clock read must actually have happened").toBeGreaterThan(
      1,
    );
    expect(r.values?.xrplLookup, "the report survives a clock that throws at write time").toBe(
      "ok",
    );
    expect(r.text ?? "").toContain("56774133566");
    expect(r.text ?? "").not.toContain("WRITE_CLOCK_SENTINEL");
  });
});

describe("silence is a fresh object, not a shared one", () => {
  it("two silent results share nothing, so one consumer cannot poison the next", async () => {
    // This is the path that runs on EVERY message the agent ever sees. A single
    // shared object is handed to every consumer in the process, so one write to
    // its values rewrites what every later no-address turn returns. It is the
    // same property the turn cache goes to trouble to hold on its own reads.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never, now: () => 1_000 });

    const a = await provider.get(
      rt(AGENT_A),
      msg("no address in here at all", randomUUID()),
      undefined as never,
    );
    expect((a.text ?? "").trim(), "setup: this must be the silent path").toBe("");

    (a.values as Record<string, unknown>).poisoned = "yes";
    (a.data as Record<string, unknown>).poisoned = "yes";

    const b = await provider.get(
      rt(AGENT_A),
      msg("still no address", randomUUID()),
      undefined as never,
    );
    expect(b, "a fresh result per call").not.toBe(a);
    expect(b.values, "fresh values").not.toBe(a.values);
    expect(b.data, "fresh data").not.toBe(a.data);
    expect(b.values?.poisoned, "nothing carried over").toBeUndefined();
    expect(b.data?.poisoned).toBeUndefined();
    expect(b.data?.xrplCache).toBe("not-cacheable");
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
