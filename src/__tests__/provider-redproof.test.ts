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
