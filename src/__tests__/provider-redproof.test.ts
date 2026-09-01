// Added after an adversarial red-proof confirmed four mutations to provider.ts
// that provider-contract.test.ts could not see.
//
// The structural cause: every failure case in that file failed at the FIRST
// network call, so the second half of the lookup was never exercised as a
// failure, and the success path was never asserted to produce text at all. The
// headline hole followed directly: silencing the account_lines refusal branch
// left the suite fully green while an address-bearing message produced empty
// text after two network calls.
//
// This file pins the contract as a property over the whole lookup rather than
// over its first step.

import { describe, expect, it, vi } from "vitest";
import { validateXrplAddress } from "../core/address.ts";
import { XRPL_NODE_URL } from "../core/node-url.ts";
import { type RefusalCode, refuse } from "../core/result.ts";
import { createXrplProvider } from "../provider.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const PEER = "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS";

const rt = {} as never;
const msg = (text: string) => ({ content: { text } }) as never;

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
    lines: [{ account: PEER, balance: "10", currency: "USD", limit: "100", limit_peer: "0" }],
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

/** Answer each JSON-RPC method with whatever the caller supplies for it. */
function fetchByMethod(map: Record<string, unknown>) {
  return vi.fn(async (_url: unknown, init?: { body?: string }) => {
    const method = String(JSON.parse(String(init?.body ?? "{}")).method ?? "");
    const body = map[method];
    if (body === undefined) throw new Error(`unexpected method ${method}`);
    return new Response(JSON.stringify(body), { status: 200 });
  });
}

describe("the SECOND half of the lookup speaks when it fails", () => {
  it("speaks when account_info succeeds and account_lines is refused", async () => {
    // THE HEADLINE HOLE. Silencing this branch was invisible to the whole suite,
    // because no test ever got past the first network call into a failure. An
    // address was present, two calls were made, and the provider contributed
    // nothing to the prompt.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: ACCOUNT_INFO_OK,
        account_lines: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect((r.text ?? "").trim().length, "a trust-line failure must be spoken").toBeGreaterThan(0);
    expect((r.text ?? "").toLowerCase()).toMatch(/refus|could not|unable|failed/);
  });

  it("speaks when account_lines returns an unreadable shape", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: ACCOUNT_INFO_OK,
        account_lines: { result: { lines: "not-an-array", validated: true, status: "success" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect((r.text ?? "").trim().length).toBeGreaterThan(0);
  });

  // D4, at the seam rather than in the renderer. The provider is the only place
  // that holds both indices, and it was discarding one of them.
  it("carries the trust lines' ledger index through to the report", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: ACCOUNT_INFO_OK, // ledger 106661700
        account_lines: { ...LINES_OK, result: { ...LINES_OK.result, ledger_index: 777777777 } },
      }) as never,
    });
    const text = (await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never)).text ?? "";
    // F2 audit: these were two toContain calls against the whole report. The
    // ledger_index line already carries 106661700 and trust_lines_ledger_index
    // already carries 777777777, so both passed without the mismatch message
    // naming either number. Anchor each to the line that must carry it.
    expect(text, "the balance's ledger must still be reported").toMatch(
      /^ {2}ledger_index: 106661700$/m,
    );
    expect(text, "the trust lines' own ledger must reach the report").toMatch(
      /^ {2}trust_lines_ledger_index: 777777777$/m,
    );
    expect(text, "the mismatch line must name BOTH ledgers").toMatch(
      /^ {2}trust_lines_ledger_mismatch: .*\b106661700\b.*\b777777777\b.*$/m,
    );
  });

  it("says nothing about a mismatch when both calls saw the same ledger", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const text = (await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never)).text ?? "";
    expect(text).toMatch(/trust_lines_ledger_index: 106661700/);
    expect(text).not.toMatch(/ledger_mismatch/i);
    expect(text).not.toMatch(/ledger_spread/i);
  });

  it("says so when the PAGES of one lookup straddled two ledgers", async () => {
    // Each page is its own request against ledger_index: validated. Two pages
    // four seconds apart can see two different ledgers, and the combined list
    // then belongs to neither.
    let page = 0;
    const provider = createXrplProvider({
      fetchImpl: vi.fn(async (_u: unknown, init?: { body?: string }) => {
        const method = String(JSON.parse(String(init?.body ?? "{}")).method ?? "");
        if (method === "account_info") {
          return new Response(JSON.stringify(ACCOUNT_INFO_OK), { status: 200 });
        }
        page += 1;
        return new Response(
          JSON.stringify({
            result: {
              account: ADDR,
              lines: [{ account: PEER, balance: "1", currency: "USD", limit: "2" }],
              ledger_index: 106661700 + page,
              validated: true,
              status: "success",
              ...(page < 3 ? { marker: `page-${page}` } : {}),
            },
          }),
          { status: 200 },
        );
      }) as never,
    });
    const text = (await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never)).text ?? "";
    expect(page, "the setup must actually have paginated").toBeGreaterThan(1);
    expect(text).toMatch(/ledger_spread/i);
  });

  it("the SUCCESS path produces a non-empty report", async () => {
    // Confirmed hole: replacing the success text with "" stayed green, because
    // nothing asserted that a fully successful lookup says anything at all.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    const text = r.text ?? "";
    expect(text.trim().length).toBeGreaterThan(0);
    expect(text).toContain(ADDR);
    expect(text).toContain("56774133566");
    expect(text).toContain("56774.133566");
    expect(r.values?.xrplLookup).toBe("ok");
  });
});

describe("an address anywhere in the message is found", () => {
  it("finds an address that appears late in a long message", async () => {
    // Confirmed hole: scanning only a 200-character prefix meant an address
    // further in produced the SILENT path, which the contract permits only when
    // no address is present at all.
    const prefix = "please look this up for me. ".repeat(12);
    expect(prefix.length).toBeGreaterThan(200);
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${prefix}the account is ${ADDR}`), undefined as never);
    expect((r.text ?? "").trim().length, "a late address must still be found").toBeGreaterThan(0);
    expect(r.text ?? "").toContain(ADDR);
  });

  it("finds a SHORT but valid classic address", async () => {
    // Confirmed hole: raising the candidate pattern's lower bound stopped short
    // addresses being detected while the checksum validator still accepted them,
    // so a real account produced silence.
    const short = "rrrrrrrrrrrrrrrrrrrrrhoLvTp";
    // Rule 95: prove the setup reached the state it claims. If this address is
    // not actually valid, the test below would be measuring nothing.
    expect(validateXrplAddress(short).ok, `${short} must be a valid address for this test`).toBe(
      true,
    );
    expect(short.length).toBeLessThan(ADDR.length);

    const infoForShort = structuredClone(ACCOUNT_INFO_OK) as Record<string, any>;
    infoForShort.result.account_data.Account = short;
    const linesForShort = structuredClone(LINES_OK) as Record<string, any>;
    linesForShort.result.account = short;

    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: infoForShort,
        account_lines: linesForShort,
      }) as never,
    });
    const r = await provider.get(rt, msg(`what about ${short}`), undefined as never);
    expect((r.text ?? "").trim().length, "a short valid address must be looked up").toBeGreaterThan(
      0,
    );
  });
});

describe("the URL that reaches the network is the one that was validated", () => {
  it("calls fetch with the allowlisted node URL and nothing else", async () => {
    // Nothing in the suite asserted the URL argument at all: the mocks spelled
    // it `_u`. That is what let a mutation return a downgraded or userinfo-
    // carrying URL from the guard while every test stayed green.
    const fetchImpl = fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);

    expect(fetchImpl.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchImpl.mock.calls) {
      const url = String(call[0]);
      expect(url).toBe(XRPL_NODE_URL);
      expect(url.startsWith("https://")).toBe(true);
      expect(url, "no credentials may reach the network").not.toContain("@");
    }
  });

  it("makes no network call at all when the address is invalid", async () => {
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    await provider.get(rt, msg("look up rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk"), undefined as never);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("the spoken-refusal contract as a property, not as a list of cases", () => {
  it("every failure shape yields non-empty text and never a bare report", async () => {
    // A sweep rather than one example per branch. Each entry fails at a
    // different point in the lookup, including after the first call succeeds.
    const shapes: Array<[string, Record<string, unknown>]> = [
      ["info error", { account_info: { result: { status: "error", error: "actNotFound" } } }],
      ["info malformed", { account_info: { result: { status: "success", validated: true } } }],
      [
        "info unvalidated",
        { account_info: { result: { ...ACCOUNT_INFO_OK.result, validated: false } } },
      ],
      [
        "lines error",
        {
          account_info: ACCOUNT_INFO_OK,
          account_lines: { result: { status: "error", error: "x" } },
        },
      ],
      [
        "lines unvalidated",
        {
          account_info: ACCOUNT_INFO_OK,
          account_lines: { result: { ...LINES_OK.result, validated: false } },
        },
      ],
      [
        "lines wrong account",
        {
          account_info: ACCOUNT_INFO_OK,
          account_lines: { result: { ...LINES_OK.result, account: PEER } },
        },
      ],
    ];

    for (const [label, map] of shapes) {
      const provider = createXrplProvider({ fetchImpl: fetchByMethod(map) as never });
      const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
      const text = (r.text ?? "").trim();
      expect(text.length, `${label}: must speak`).toBeGreaterThan(0);
      expect(text.toLowerCase(), `${label}: must read as a refusal`).toMatch(
        /refus|could not|unable|failed|not exist|not found/,
      );
      expect(text, `${label}: must not look like a balance report`).not.toContain(
        "xrp_balance_drops",
      );
    }
  });
});

// D6, the provider half, and the one place X-006 recorded this package breaking
// its own rule: run() takes candidates[0] and discards every other address in
// the message with no word.
//
// Nothing here changes WHICH address is looked up. One lookup is still one
// account. What changes is that the omission is now counted and spoken, on the
// success path and on every refusal path alike, because a refusal about the
// first address in a message naming three reads as an answer about all three.
describe("a second address in the message is counted, never silently dropped", () => {
  // A third valid classic address, shorter than the other two. Rule 95: if
  // any of these were not valid the tests below would measure nothing.
  const SHORT = "rrrrrrrrrrrrrrrrrrrrrhoLvTp";
  /** Valid charset and length, bad checksum. rippled called this actMalformed. */
  const BAD = "rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk";

  it("the addresses this suite relies on are what it says they are", () => {
    expect(validateXrplAddress(ADDR).ok, ADDR).toBe(true);
    expect(validateXrplAddress(PEER).ok, PEER).toBe(true);
    expect(validateXrplAddress(SHORT).ok, SHORT).toBe(true);
    expect(validateXrplAddress(BAD).ok, BAD).toBe(false);
    expect(new Set([ADDR, PEER, SHORT]).size, "three distinct addresses").toBe(3);
  });

  it("THRESHOLD: exactly one further address is reported as 1", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`compare ${ADDR} and ${PEER}`), undefined as never);
    expect(r.text ?? "").toMatch(/^ {2}other_addresses_not_looked_up: 1\b/m);
  });

  it("counts EVERY further address, not merely that there were some", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} then ${PEER} then ${SHORT}`), undefined as never);
    expect(r.text ?? "").toMatch(/^ {2}other_addresses_not_looked_up: 2\b/m);
  });

  it("still looks up only the first, and the others never reach the network", async () => {
    // The behaviour is unchanged and has to stay unchanged. Counting an omission
    // is not the same as retrieving it, and a fix that quietly started issuing a
    // request per address would be a different package.
    const fetchImpl = fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    await provider.get(rt, msg(`${ADDR} and ${PEER}`), undefined as never);

    expect(fetchImpl.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchImpl.mock.calls) {
      const body = String((call[1] as { body?: string } | undefined)?.body ?? "");
      expect(body, "the first address is the one looked up").toContain(ADDR);
      expect(body, "no other address may reach the node").not.toContain(PEER);
    }
  });

  it("a REFUSAL about the first address still counts the ones behind it", async () => {
    // The case that makes this a security property rather than a nicety. The
    // first candidate fails its checksum, so the lookup refuses and stops. A
    // valid address sat behind it and was never tried, and saying only "that
    // address was refused" invites the model to answer about the other one.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`check ${BAD} and ${ADDR}`), undefined as never);

    expect(fetchImpl, "a bad address must never reach the network").not.toHaveBeenCalled();
    expect((r.text ?? "").toLowerCase(), "it must still read as a refusal").toMatch(/refus/);
    expect(r.text ?? "").toMatch(/other_addresses_not_looked_up: 1\b/);
  });

  it("counts a further address even when the lookup fails at the node", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${PEER}`), undefined as never);
    expect(r.text ?? "").toMatch(/other_addresses_not_looked_up: 1\b/);
  });

  it("says nothing at all when the message named ONE address", async () => {
    // The negative control. A notice that always fires satisfies every
    // assertion above and means nothing.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.text ?? "").not.toMatch(/other_addresses/i);
  });

  it("says nothing on a refusal that named ONE address", async () => {
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, msg(`look up ${BAD}`), undefined as never);
    expect((r.text ?? "").toLowerCase()).toMatch(/refus/);
    expect(r.text ?? "").not.toMatch(/other_addresses/i);
  });

  it("does NOT report the same address written twice as a further address", async () => {
    // Overstating an omission is the same class of inaccuracy as hiding one, in
    // a report whose only job is to be accurate. The second mention is the
    // address that WAS looked up.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR}, and again ${ADDR}`), undefined as never);
    expect(r.text ?? "").not.toMatch(/other_addresses/i);
  });

  it("counts a skipped candidate without claiming it is a real account", async () => {
    // The skipped strings are never validated, so the notice may not assert
    // they are accounts. It reports what it did: it did not look at them.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${BAD}`), undefined as never);
    const text = r.text ?? "";
    expect(text).toMatch(/^ {2}other_addresses_not_looked_up: 1\b/m);
    expect(text).toMatch(/neither validated nor retrieved/i);
  });

  it("does NOT double-count a LATER address that appears twice", async () => {
    // The duplicate test above writes the repeat as the FIRST address, and
    // `[A, A]` yields 0 whether the count is a Set or a plain length, so that
    // test cannot see the difference. `[A, B, B]` can: one further address was
    // named, twice, and the honest count is 1.
    //
    // Overstating an omission is the same class of inaccuracy as hiding one, in
    // a report whose only job is to be accurate.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });

    const twice = await provider.get(
      rt,
      msg(`${ADDR} then ${PEER} then ${PEER}`),
      undefined as never,
    );
    expect(twice.text ?? "", "one further address named twice is ONE").toMatch(
      /^ {2}other_addresses_not_looked_up: 1\b/m,
    );

    // And a mixture, so the count is neither "distinct minus one" by accident
    // nor the raw mention count.
    const mixed = await provider.get(
      rt,
      msg(`${ADDR} then ${PEER} then ${PEER} then ${SHORT} then ${ADDR}`),
      undefined as never,
    );
    expect(mixed.text ?? "", "two distinct further addresses, five mentions, is TWO").toMatch(
      /^ {2}other_addresses_not_looked_up: 2\b/m,
    );
  });
});

// Three more values this file's path emits survived a source-side enumeration:
// each was replaced with a word that could not appear otherwise and the suite
// stayed green. All three are text the model reads on a failure, which is the
// only text it gets when a lookup does not succeed.
describe("a failure report quotes the failure that actually happened", () => {
  it("quotes the ACTUAL HTTP status the node answered with", async () => {
    // Several statuses, each of which must appear verbatim. One example would
    // be satisfied by hardcoding that one number.
    for (const status of [500, 503, 418]) {
      const provider = createXrplProvider({
        fetchImpl: vi.fn(async () => new Response("{}", { status })) as never,
      });
      const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
      expect(r.text ?? "", `HTTP ${status}`).toContain(`answered with HTTP ${status},`);
    }
  });

  it("quotes the ACTUAL timeout it waited, not a constant", async () => {
    for (const timeoutMs of [37, 91]) {
      const hangs = vi.fn(
        async (_url: unknown, init?: { signal?: AbortSignal }) =>
          await new Promise<Response>((_res, rej) => {
            init?.signal?.addEventListener("abort", () => rej(new Error("aborted")));
          }),
      );
      const provider = createXrplProvider({ timeoutMs, fetchImpl: hangs as never });
      const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
      expect(r.text ?? "", `${timeoutMs}ms`).toContain(`did not answer within ${timeoutMs}ms,`);
    }
  });

  it("the outer catch names the ERROR TYPE it caught", async () => {
    // Invariant 1's last line of defence. It already had a test proving it
    // speaks; nothing read WHAT it said, so the one identifying detail in the
    // message could have been any fixed string.
    const throwing = (error: Error) =>
      ({
        get content(): { text: string } {
          throw error;
        },
      }) as never;

    for (const error of [new TypeError("hostile getter"), new RangeError("hostile getter")]) {
      const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
      const r = await provider.get(rt, throwing(error), undefined as never);
      expect(r.text ?? "", error.name).toContain(`(${error.name})`);
      expect(r.values?.xrplRefusalCode).toBe("INTERNAL_ERROR");
    }
  });
});

// `refuse` forces a non-empty message so that one empty message is not one
// silently missing report. The fallback names the CODE, and nothing read it, so
// the last thing a blank refusal can say about itself was unpinned.
describe("a refusal with nothing to say still names itself", () => {
  it("substitutes the REAL code when the message is empty or whitespace", () => {
    const codes: RefusalCode[] = ["NODE_TIMEOUT", "RATE_LIMITED", "INTERNAL_ERROR"];
    for (const code of codes) {
      for (const blank of ["", "   ", "\n\t "]) {
        const r = refuse(code, blank);
        expect(r.ok).toBe(false);
        expect(r.message.trim(), `${code} must not be blank`).not.toBe("");
        expect(r.message, `${code} must name itself`).toBe(`Refused: ${code}.`);
      }
    }
  });
});
