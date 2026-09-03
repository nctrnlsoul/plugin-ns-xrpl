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

import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  ADDRESS_CANDIDATE_PATTERN,
  countUnreadableAddressRuns,
  validateXrplAddress,
} from "../core/address.ts";
import { BOUNDS } from "../core/bounds.ts";
import { XRPL_NODE_URL } from "../core/node-url.ts";
import { type RefusalCode, refuse } from "../core/result.ts";
import { createXrplProvider } from "../provider.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const PEER = "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS";

const BASE58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

/**
 * Distinct valid classic addresses, BUILT rather than pasted.
 *
 * Sixty hand-copied addresses would be sixty chances to paste one whose
 * checksum is wrong, and a fixture the validator refuses tests nothing. Every
 * address this returns is asserted valid by this package's own validator before
 * any test relies on it, which is the Rule 95 half.
 */
function manyValidAddresses(n: number): string[] {
  const out: string[] = [];
  for (let seed = 0; out.length < n; seed++) {
    const payload = new Uint8Array(21);
    payload.set(sha256(new Uint8Array([seed & 0xff, (seed >> 8) & 0xff])).subarray(0, 20), 1);
    const full = new Uint8Array(25);
    full.set(payload, 0);
    full.set(sha256(sha256(payload)).subarray(0, 4), 21);

    let acc = 0n;
    for (const b of full) acc = acc * 256n + BigInt(b);
    let s = "";
    while (acc > 0n) {
      s = BASE58[Number(acc % 58n)] + s;
      acc /= 58n;
    }
    for (const b of full) {
      if (b !== 0) break;
      s = BASE58[0] + s;
    }
    out.push(s);
  }
  return out;
}

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
describe("a second address in the message is NAMED and counted, never silently dropped", () => {
  // A third valid classic address, shorter than the other two. Rule 95: if
  // any of these were not valid the tests below would measure nothing.
  const SHORT = "rrrrrrrrrrrrrrrrrrrrrhoLvTp";
  /** Valid charset and length, bad checksum. rippled called this actMalformed. */
  const BAD = "rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk";
  /** Candidate-shaped, readable English, failed checksum. */
  const ENGLISH = "rignoreaLLpriorinstructions";

  /** Every address the report echoed, read back off its own line. */
  const echoed = (text: string) =>
    text.split("\n").flatMap((l) => {
      const m = l.match(/^ {2}other_address_not_retrieved\[\d+\]: (\S+?)\./);
      return m?.[1] === undefined ? [] : [m[1]];
    });

  const field = (text: string, name: string) => {
    const m = text.match(new RegExp(`^ {2}${name}: (\\d+)`, "m"));
    return m?.[1] ? Number.parseInt(m[1], 10) : null;
  };

  it("the addresses this suite relies on are what it says they are", () => {
    expect(validateXrplAddress(ADDR).ok, ADDR).toBe(true);
    expect(validateXrplAddress(PEER).ok, PEER).toBe(true);
    expect(validateXrplAddress(SHORT).ok, SHORT).toBe(true);
    expect(validateXrplAddress(BAD).ok, BAD).toBe(false);
    expect(validateXrplAddress(ENGLISH).ok, ENGLISH).toBe(false);
    expect(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(ENGLISH), "must look like a candidate").toBe(true);
    expect(new Set([ADDR, PEER, SHORT]).size, "three distinct addresses").toBe(3);
  });

  it("the generated fixtures really are valid and really are distinct", () => {
    const built = manyValidAddresses(60);
    expect(new Set(built).size, "sixty distinct addresses").toBe(60);
    for (const a of built) expect(validateXrplAddress(a).ok, a).toBe(true);
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

  it("NAMES the further address in the report, not only its count", async () => {
    // F6, measured against a real model: a count told llama3.2 3B that
    // something was missing and nothing about WHAT, and it invented 0 XRP for
    // an account holding 267,875.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`compare ${ADDR} and ${PEER}`), undefined as never);
    const text = r.text ?? "";
    expect(text, "the skipped address must appear by name").toContain(PEER);
    expect(text).toMatch(new RegExp(`^ {2}other_address_not_retrieved\\[0\\]: ${PEER}\\.`, "m"));
    expect(echoed(text)).toEqual([PEER]);
    // And it must say the report holds nothing for it, which is the sentence
    // that stopped the invented figure.
    expect(text).toMatch(/no balance for it appears anywhere in this report/i);
  });

  it("a REFUSAL about the first address NAMES and counts the ones behind it", async () => {
    // The case that makes this a security property rather than a nicety. The
    // first candidate fails its checksum, so the lookup refuses and stops. A
    // valid address sat behind it and was never tried, and saying only "that
    // address was refused" invites the model to answer about the other one.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`check ${BAD} and ${ADDR}`), undefined as never);

    expect(fetchImpl, "a bad address must never reach the network").not.toHaveBeenCalled();
    expect((r.text ?? "").toLowerCase(), "it must still read as a refusal").toMatch(/refus/);
    // TWO, because a refusal describes nothing and so has no subject to exclude:
    // the string it is refusing is in the count with the address behind it.
    expect(r.text ?? "").toMatch(/other_addresses_not_looked_up: 2\b/);
    expect(r.text ?? "", "and the sentence says the subject is included").toMatch(
      /INCLUDING the one this refusal is about/,
    );
    expect(echoed(r.text ?? ""), "a refusal carries the names too").toEqual([ADDR]);
    expect(field(r.text ?? "", "other_addresses_not_valid"), "and the bad one is counted").toBe(1);
  });

  it("a refusal behind SIXTY further addresses names some and stays inside the cap", async () => {
    // A refusal message IS report content, and speak() had no size cap at all:
    // every MAX_RENDERED_CHARS assertion in the suite was on the success path.
    // The bound lives in the shared notice renderer so both callers inherit it.
    const many = manyValidAddresses(60);
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(
      rt,
      msg(`check ${BAD} then ${many.join(" ")}`),
      undefined as never,
    );
    const text = r.text ?? "";

    expect(fetchImpl, "a bad address must never reach the network").not.toHaveBeenCalled();
    expect(text.toLowerCase()).toMatch(/refus/);
    expect(text.length, "a refusal is report content and is bounded too").toBeLessThanOrEqual(
      BOUNDS.MAX_RENDERED_CHARS,
    );
    expect(field(text, "other_addresses_not_looked_up"), "sixty plus the refused one").toBe(61);
    expect(echoed(text), "and the cap decides how many are named").toHaveLength(
      BOUNDS.MAX_ECHOED_ADDRESSES,
    );
    expect(field(text, "other_addresses_not_named_cap"), "the unnamed rest are stated").toBe(
      60 - BOUNDS.MAX_ECHOED_ADDRESSES,
    );
    // And the reason is the POLICY CAP, which is the one that is true here.
    // This refusal is 1,229 of 4,000 characters, so a notice claiming the size
    // bound held these addresses back would be stating something false in the
    // only text the model gets when a lookup fails.
    expect(text.length, "setup: there is room to spare").toBeLessThan(BOUNDS.MAX_RENDERED_CHARS);
    expect(text, "so it must not claim a size reason it cannot support").not.toMatch(
      /other_addresses_not_named_for_room/,
    );
    for (const a of echoed(text)) expect(a).toMatch(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
  });

  it("fifty address-shaped tokens do not blow the report, and the omission is spoken", async () => {
    const many = manyValidAddresses(51);
    const first = many[0] ?? "";
    const infoFor = structuredClone(ACCOUNT_INFO_OK) as Record<string, any>;
    infoFor.result.account_data.Account = first;
    const linesFor = structuredClone(LINES_OK) as Record<string, any>;
    linesFor.result.account = first;

    const fetchImpl = fetchByMethod({ account_info: infoFor, account_lines: linesFor });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(many.join(" ")), undefined as never);
    const text = r.text ?? "";

    expect(text.length).toBeLessThanOrEqual(BOUNDS.MAX_RENDERED_CHARS);
    expect(field(text, "other_addresses_not_looked_up")).toBe(50);
    expect(echoed(text)).toHaveLength(BOUNDS.MAX_ECHOED_ADDRESSES);
    expect(field(text, "other_addresses_not_named_cap")).toBe(50 - BOUNDS.MAX_ECHOED_ADDRESSES);

    // ONE lookup. Counting an omission is not the same as retrieving it, and
    // nothing here may turn into a request per address.
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchImpl.mock.calls) {
      const body = String((call[1] as { body?: string } | undefined)?.body ?? "");
      expect(body, "only the first address may reach the node").toContain(first);
      for (const other of many.slice(1)) expect(body).not.toContain(other);
    }
  });

  it("NEVER quotes a candidate that failed its checksum, however readable it is", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${ENGLISH}`), undefined as never);
    const text = r.text ?? "";
    expect(text, "the readable candidate must not reach the prompt").not.toContain(ENGLISH);
    expect(text.toLowerCase()).not.toContain("ignore");
    expect(field(text, "other_addresses_not_looked_up"), "it is still counted").toBe(1);
    expect(field(text, "other_addresses_not_valid")).toBe(1);
    expect(echoed(text)).toEqual([]);
  });

  it("counts a further address even when the lookup fails at the node", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${PEER}`), undefined as never);
    expect(r.text ?? "").toMatch(/other_addresses_not_looked_up: 2\b/);
    expect(
      echoed(r.text ?? ""),
      "and BOTH are named, the one the user asked about included",
    ).toEqual([ADDR, PEER]);
  });

  it("says nothing at all when the message named ONE address", async () => {
    // The negative control. A notice that always fires satisfies every
    // assertion above and means nothing.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.text ?? "", "no aggregate line and no named line").not.toMatch(/other_address/i);
  });

  it("a refusal about ONE INVALID string counts it and NEVER quotes it", async () => {
    // This used to assert the refusal said nothing at all, which was the F9
    // defect stated as a requirement: the one entity the message named got no
    // line and no guard. It is counted now. It is still never NAMED, because it
    // fails the checksum and the base58 class spells English.
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, msg(`look up ${BAD}`), undefined as never);
    const text = r.text ?? "";
    expect(text.toLowerCase()).toMatch(/refus/);
    expect(field(text, "other_addresses_not_looked_up")).toBe(1);
    expect(field(text, "other_addresses_not_valid")).toBe(1);
    expect(text, "an unvalidated candidate is counted, never quoted").not.toContain(BAD);
    expect(echoed(text)).toEqual([]);
  });

  it("a refusal about ONE VALID address NAMES it and forbids a balance for it", async () => {
    // F9, and it is F6's own lesson inverted. MEASURED before the fix: on
    // `compare A and B and C` with the node answering an error, B and C each
    // got "no balance may be stated for it" and A, the account the user
    // actually asked about, got no name, no line and no guard at all.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    const text = r.text ?? "";
    expect(text.toLowerCase()).toMatch(/refus/);
    expect(echoed(text), "the subject of the refusal is named").toEqual([ADDR]);
    const named = text.split("\n").find((l) => l.includes("other_address_not_retrieved[0]")) ?? "";
    expect(named, "and guarded exactly like every other address").toMatch(
      /and none may be stated for it\.$/,
    );
    expect(named, "with a clause that is TRUE on a path that retrieved nothing").toMatch(
      /no ledger data was retrieved for it/,
    );
  });

  it("EVERY named address is guarded on a refusal, the subject included", async () => {
    // The property over the set, which is what the finding was really about.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(
      rt,
      msg(`compare ${ADDR} and ${PEER} and ${SHORT}`),
      undefined as never,
    );
    const text = r.text ?? "";
    const names = echoed(text);
    expect(names, "all three, in the order the message named them").toEqual([ADDR, PEER, SHORT]);
    for (const line of text.split("\n").filter((l) => /other_address_not_retrieved\[/.test(l))) {
      expect(line, line).toMatch(/and none may be stated for it\.$/);
    }
  });

  it("the aggregate on a refusal never claims a description that does not exist", async () => {
    // The second half of the same finding. A refusal describes NOTHING, and the
    // sentence said "not counting the one this report describes", which asserts
    // a description exists. It is report content, so it has to be true.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${PEER}`), undefined as never);
    const line =
      (r.text ?? "").split("\n").find((l) => l.includes("other_addresses_not_looked_up")) ?? "";
    expect(line, "setup: the aggregate must be present").toContain(
      "other_addresses_not_looked_up: 2",
    );
    expect(line, "it must not claim a description that does not exist").not.toMatch(
      /not counting the one this report describes/,
    );
    expect(line, "nor claim this refusal describes anything").toMatch(
      /nothing in this report describes any of them/,
    );
    expect(line, "and must say the subject is inside the count").toMatch(
      /INCLUDING the one this refusal is about/,
    );
  });

  it("a RATE LIMIT refusal names the other addresses too", async () => {
    // P11. MEASURED: passing an empty list here shrank the refusal from 661
    // characters to 157 and the suite stayed green. A refusal is the only text
    // the model gets, and this one is produced on a turn that named several
    // accounts.
    const fetchImpl = fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    for (let i = 0; i < BOUNDS.RATE_LIMIT_MAX_REQUESTS; i++) {
      await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    }
    const r = await provider.get(rt, msg(`${ADDR} and ${PEER}`), undefined as never);
    expect(r.values?.xrplRefusalCode, "setup: the limiter must really be exhausted").toBe(
      "RATE_LIMITED",
    );
    expect(echoed(r.text ?? ""), "both accounts are named").toEqual([ADDR, PEER]);
    expect(field(r.text ?? "", "other_addresses_not_looked_up")).toBe(2);
  });

  it("an account_lines refusal names the other addresses too", async () => {
    // P12, the same hole on the second half of the lookup: 606 characters to
    // 102 with the suite green.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: ACCOUNT_INFO_OK,
        account_lines: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${PEER}`), undefined as never);
    expect((r.text ?? "").toLowerCase()).toMatch(/refus/);
    expect(echoed(r.text ?? ""), "both accounts are named").toEqual([ADDR, PEER]);
    expect(field(r.text ?? "", "other_addresses_not_looked_up")).toBe(2);
  });

  it("does NOT report the same address written twice as a further address", async () => {
    // Overstating an omission is the same class of inaccuracy as hiding one, in
    // a report whose only job is to be accurate. The second mention is the
    // address that WAS looked up.
    //
    // Naming made this sharper than a count could. With `candidates.slice(1)`
    // instead of `c !== first`, the report prints `address: A` with a real
    // balance AND a line saying A was not retrieved and no balance for it
    // appears in this report. A self-contradicting report is worse than the
    // silence this whole change exists to remove.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR}, and again ${ADDR}`), undefined as never);
    const text = r.text ?? "";
    expect(text).not.toMatch(/other_address/i);
    expect(echoed(text), "the looked-up address must never be named as skipped").toEqual([]);
    expect(text, "and it is still the address the report describes").toMatch(
      new RegExp(`^ {2}address: ${ADDR}$`, "m"),
    );
  });

  it("a REFUSAL counts the address it is refusing ONCE, however often the message repeats it", async () => {
    // `c !== first` is the REFUSAL path's only protection, and it is the half
    // the renderer cannot do. On the report path the renderer removes the
    // address it is reporting on by itself; a refusal has no subject to hand it,
    // so `candidates.slice(1)` here would count, and describe as unretrieved,
    // the very address the refusal is about.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(
      rt,
      msg(`${BAD} and ${ADDR} and again ${BAD}`),
      undefined as never,
    );
    const text = r.text ?? "";

    expect(fetchImpl, "a bad address must never reach the network").not.toHaveBeenCalled();
    expect(text.toLowerCase()).toMatch(/refus/);
    // TWO DISTINCT entities, and the repeated one counted ONCE. `c !== first`
    // no longer removes the subject from a refusal, because F9 requires the
    // subject to be named and guarded; what still must not happen is the same
    // string counted twice.
    expect(field(text, "other_addresses_not_looked_up"), "two distinct, three mentions").toBe(2);
    expect(echoed(text)).toEqual([ADDR]);
    expect(field(text, "other_addresses_not_valid"), "and the repeated bad one counts once").toBe(
      1,
    );
  });

  it("never contradicts itself about A when the message reads A then B then A", async () => {
    // The interleaved form, which `[A, A]` cannot distinguish: a naive
    // `slice(1)` yields [B, A] here, so A would be both described and declared
    // not retrieved inside one report.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} then ${PEER} then ${ADDR}`), undefined as never);
    const text = r.text ?? "";
    expect(echoed(text), "only the address that was truly skipped").toEqual([PEER]);
    expect(field(text, "other_addresses_not_looked_up")).toBe(1);
  });

  it("counts a skipped candidate without claiming it is a real account", async () => {
    // The skipped strings that fail validation are never named, so the notice
    // may not assert they are accounts. It reports what it did: it did not look
    // at them, and it did not retrieve anything for them.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`${ADDR} and ${BAD}`), undefined as never);
    const text = r.text ?? "";
    expect(text).toMatch(/^ {2}other_addresses_not_looked_up: 1\b/m);
    expect(text).toMatch(/no ledger data was retrieved for any of the rest/i);
    expect(text, "the old wording is now false and must be gone").not.toMatch(
      /neither validated nor retrieved/i,
    );
    expect(text, "an unvalidated candidate is counted, never quoted").not.toContain(BAD);
    expect(field(text, "other_addresses_not_valid")).toBe(1);
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
    expect(echoed(mixed.text ?? ""), "and both are named").toEqual([PEER, SHORT]);
  });

  it("the OUTER CATCH claims nothing about other addresses, because it measured none", async () => {
    // Invariant 10's one deliberate exception, and it must stay one. run() can
    // throw before it has read the message at all, so this branch does not know
    // whether the message named any address. Saying nothing is the only claim it
    // can support, and an empty list has to render exactly as the old zero did.
    const hostile = {
      content: {
        get text(): string {
          throw new Error("GETTER_SENTINEL");
        },
      },
    };
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, hostile as never, undefined as never);
    expect(r.values?.xrplRefusalCode).toBe("INTERNAL_ERROR");
    expect((r.text ?? "").trim().length, "it must still SPEAK").toBeGreaterThan(0);
    expect(r.text ?? "", "and claim nothing it never measured").not.toMatch(/other_address/i);
  });
});

// F8. THE WORSE CASE THAN A WRONG REPORT: NO REPORT.
//
// ADDRESS_CANDIDATE_PATTERN is ASCII-only, so one invisible character inside an
// address makes the address invisible to the scanner. MEASURED against the
// shipped build: a message holding only
//   "rHb9CJAWyB4rj91VRWn9" + U+200B + "6DkukG4bwdtyTh"
// produced ZERO candidates, so run() returned silent(), text.length was 0, and
// no network call was made. On this runtime an empty provider text contributes
// zero characters to the prompt, so the model answered an XRPL question about a
// named account from its own priors with nothing anywhere saying a lookup had
// been attempted, refused, or skipped.
//
// Nothing here changes WHICH address is looked up, and that is deliberate.
// Refusing the whole turn whenever a poisoned run is present would let one
// pasted zero-width space silence every XRPL lookup at zero attacker cost. The
// substitution hazard is closed by SPEECH.
describe("a run this plugin could not read is spoken, never silent and never normalised", () => {
  // Written as an escape, never as the character. CLAUDE.md bans literal
  // invisible characters in source and checks/failopen_lint.ts fails on them.
  const ZWSP = "\u200B";
  /** ADDR with one zero-width space after its twentieth visible character. */
  const POISONED = `${ADDR.slice(0, 20)}${ZWSP}${ADDR.slice(20)}`;
  /** A SECOND hidden account, so a count of two can be a count of two accounts. */
  const POISONED_PEER = `${PEER.slice(0, 20)}${ZWSP}${PEER.slice(20)}`;
  /** Valid charset and length, bad checksum. rippled called this actMalformed. */
  const BAD = "rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk";

  const infoFor = (account: string) => {
    const clone = structuredClone(ACCOUNT_INFO_OK) as Record<string, any>;
    clone.result.account_data.Account = account;
    return clone;
  };
  const linesFor = (account: string) => {
    const clone = structuredClone(LINES_OK) as Record<string, any>;
    clone.result.account = account;
    return clone;
  };

  const field = (text: string, name: string) => {
    const m = text.match(new RegExp(`^ {2}${name}: (\\d+)`, "m"));
    return m?.[1] ? Number.parseInt(m[1], 10) : null;
  };

  it("the fixture is what this block claims it is", () => {
    // Rule 95: prove the setup. If the poisoned run still produced a candidate
    // there would be no silence to remove and every test below would be
    // measuring the ordinary refusal path.
    expect(validateXrplAddress(ADDR).ok, "the base address must be real").toBe(true);
    expect(POISONED.includes(ZWSP), "the run must actually carry a splitter").toBe(true);
    expect(POISONED.match(ADDRESS_CANDIDATE_PATTERN), "and produce NO candidate").toBeNull();
    expect(
      countUnreadableAddressRuns(POISONED, POISONED.match(ADDRESS_CANDIDATE_PATTERN)),
      "and be counted exactly once",
    ).toBe(1);
    expect(validateXrplAddress(BAD).ok).toBe(false);
  });

  it("a message holding ONLY a poisoned run SPEAKS, and makes no network call", async () => {
    // THE headline case. Before this change: text.length 0, zero fetches, and
    // nothing in the prompt to say an entity had been named at all.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`what is the balance of ${POISONED}`), undefined as never);
    const text = r.text ?? "";

    expect(
      fetchImpl,
      "nothing may be charged before every check has passed",
    ).not.toHaveBeenCalled();
    expect(text.trim().length, "it must SPEAK").toBeGreaterThan(0);
    expect(r.values?.xrplRefusalCode, "and for the reason it names").toBe("NO_READABLE_ADDRESS");
    expect(text.toLowerCase()).toMatch(/refus/);
    expect(text).toMatch(/^ {2}addresses_hidden_by_invisible_characters: 1\b/m);
    expect(r.data?.xrplHiddenAddresses, "and the count is visible off-prompt too").toBe(1);
    expect(r.data?.xrplCache, "nothing read the ledger, so there is nothing to replay").toBe(
      "not-cacheable",
    );
  });

  it("NEVER ECHOES the run it could not read, as a positive property", async () => {
    // "Does not contain the run" is weaker than "contains only printable
    // ASCII". The scanner returns a NUMBER and never the strings, so there is
    // structurally nothing to print; this asserts the consequence.
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, msg(`check ${POISONED} please`), undefined as never);
    const text = r.text ?? "";
    expect(text, "the run must not survive whole").not.toContain(POISONED);
    expect(text, "nor in part: twenty base58 characters already read as an address").not.toContain(
      ADDR.slice(0, 20),
    );
    expect(text, "and no invisible character may reach the prompt").not.toContain(ZWSP);
    for (const line of text.split("\n")) {
      expect(line, JSON.stringify(line)).toMatch(/^[\x20-\x7E]*$/);
    }
  });

  it("does NOT normalise the run away and look up what it would have been", async () => {
    // The NO NORMALISATION rule, end to end. Repairing the run would look up an
    // address the message never actually contained, which is the validator
    // behaviour src/core/address.ts refuses by name one layer down.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    await provider.get(rt, msg(`balance of ${POISONED}`), undefined as never);
    expect(fetchImpl, "a repaired address is still an address nobody typed").not.toHaveBeenCalled();
  });

  it("SPEAKS at every splitter position, and says the omission exactly ONCE", async () => {
    // The sweep, through the real provider rather than the scanner. Below 25
    // visible characters there is no candidate at all, so the refusal is
    // NO_READABLE_ADDRESS and the run is what carries the omission. At 25 and
    // above the prefix IS candidate-shaped and fails its checksum, so the
    // refusal is ADDRESS_MALFORMED and the entity is already reported by that:
    // counting the run as well would state one omission twice, which is what
    // the first version of this test asserted and what an adversarial pass
    // reproduced as `other_addresses_not_valid: 1` beside
    // `addresses_hidden_by_invisible_characters: 1` for one account.
    //
    // Every k must SPEAK, and every k must say it once. Neither band may touch
    // the network.
    const seen = new Set<string>();
    for (let k = 1; k <= ADDR.length - 1; k++) {
      const fetchImpl = vi.fn();
      const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
      const poisoned = `${ADDR.slice(0, k)}${ZWSP}${ADDR.slice(k)}`;
      const r = await provider.get(rt, msg(`look up ${poisoned}`), undefined as never);
      const text = r.text ?? "";

      expect(fetchImpl, `k=${k} must not reach the network`).not.toHaveBeenCalled();
      expect(text.trim().length, `k=${k} must speak`).toBeGreaterThan(0);
      const code = String(r.values?.xrplRefusalCode);
      expect(code, `k=${k}`).toBe(k < 25 ? "NO_READABLE_ADDRESS" : "ADDRESS_MALFORMED");
      seen.add(code);

      if (k < 25) {
        expect(text, `k=${k}: nothing else reported this, so the run must`).toMatch(
          /^ {2}addresses_hidden_by_invisible_characters: 1\b/m,
        );
        expect(r.data?.xrplHiddenAddresses, `k=${k}`).toBe(1);
        continue;
      }
      expect(
        text,
        `k=${k}: the refusal already reports this entity, so the run must NOT be counted too`,
      ).not.toMatch(/addresses_hidden_by_invisible_characters/);
      expect(r.data?.xrplHiddenAddresses, `k=${k}`).toBe(0);
    }
    // Rule 95: prove the sweep reached BOTH bands. One band alone would test
    // half the property and read as the whole of it.
    expect([...seen].sort(), "both bands must be covered").toEqual([
      "ADDRESS_MALFORMED",
      "NO_READABLE_ADDRESS",
    ]);
  });

  it("a valid address with a splitter TOUCHING it is described, and never denied", async () => {
    // F1 end to end, and it is the worst shape this change could have shipped:
    // one report saying `address: A` with a real balance AND saying no address
    // was read from that run and that the account described was not taken from
    // it. Both sentences about the same run. MEASURED before the fix.
    const fetchImpl = fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(
      rt,
      msg(`what is the balance of ${ADDR}${ZWSP}a`),
      undefined as never,
    );
    const text = r.text ?? "";

    expect(r.values?.xrplLookup, "setup: the address must really be looked up").toBe("ok");
    expect(text).toMatch(new RegExp(`^ {2}address: ${ADDR}$`, "m"));
    expect(text, "the report must not deny the account it just described").not.toMatch(
      /addresses_hidden_by_invisible_characters/,
    );
    expect(r.data?.xrplHiddenAddresses).toBe(0);
  });

  it("a further address carrying a splitter is ONE omission, not two", async () => {
    // F7 end to end. B is a valid address with a splitter at visible index 30,
    // so the candidate scanner reads a cut prefix out of it and the report
    // counts that as an unvalidated candidate. The message named ONE further
    // account, so the report must state ONE omission for it.
    const poisonedPeer = `${PEER.slice(0, 30)}${ZWSP}${PEER.slice(30)}`;
    const fetchImpl = fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`${ADDR} and ${poisonedPeer}`), undefined as never);
    const text = r.text ?? "";

    expect(field(text, "other_addresses_not_looked_up"), "one further entity").toBe(1);
    expect(field(text, "other_addresses_not_valid"), "reported as an unvalidated candidate").toBe(
      1,
    );
    expect(text, "and NOT a second time as an unreadable run").not.toMatch(
      /addresses_hidden_by_invisible_characters/,
    );
  });

  it("describes the address it CAN read and still says a run was unreadable", async () => {
    // The two-address case from the reproduction. The report is about B, which
    // is correct and unchanged; what changes is that A is no longer erased.
    const fetchImpl = fetchByMethod({
      account_info: infoFor(PEER),
      account_lines: linesFor(PEER),
    });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`pay ${POISONED} and ${PEER}`), undefined as never);
    const text = r.text ?? "";

    expect(r.values?.xrplLookup, "setup: B really was looked up").toBe("ok");
    expect(text).toMatch(new RegExp(`^ {2}address: ${PEER}$`, "m"));
    expect(text, "and the run beside it is stated").toMatch(
      /^ {2}addresses_hidden_by_invisible_characters: 1\b/m,
    );
    expect(r.data?.xrplHiddenAddresses).toBe(1);
    expect(text, "the run itself never reaches the prompt").not.toContain(ADDR.slice(0, 20));
    expect(text, "and the report says the account it describes did not come from one").toMatch(
      /Any account described in this report was NOT taken from one of them\./,
    );
  });

  it("still looks up ONLY the readable address, and the repaired one never reaches the node", async () => {
    const fetchImpl = fetchByMethod({
      account_info: infoFor(PEER),
      account_lines: linesFor(PEER),
    });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    await provider.get(rt, msg(`pay ${POISONED} and ${PEER}`), undefined as never);

    expect(fetchImpl.mock.calls.length).toBeGreaterThan(0);
    for (const call of fetchImpl.mock.calls) {
      const body = String((call[1] as { body?: string } | undefined)?.body ?? "");
      expect(body, "the readable address is the one looked up").toContain(PEER);
      expect(body, "the poisoned run must never be repaired into a request").not.toContain(ADDR);
    }
  });

  it("THRESHOLD: one hidden address is 1, two DISTINCT ones are 2", async () => {
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const one = await provider.get(rt, msg(`send to ${POISONED}`), undefined as never);
    expect(one.text ?? "").toMatch(/^ {2}addresses_hidden_by_invisible_characters: 1\b/m);

    const two = await provider.get(
      rt,
      msg(`${POISONED} then ${POISONED_PEER}`),
      undefined as never,
    );
    expect(two.text ?? "").toMatch(/^ {2}addresses_hidden_by_invisible_characters: 2\b/m);
    expect(two.data?.xrplHiddenAddresses).toBe(2);
  });

  it("counts the SAME hidden account named twice as ONE", async () => {
    // DISTINCT, matching the doctrine other_addresses_not_looked_up follows.
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, msg(`${POISONED} then again ${POISONED}`), undefined as never);
    expect(r.text ?? "").toMatch(/^ {2}addresses_hidden_by_invisible_characters: 1\b/m);
  });

  it("does NOT report an account the report already describes as hidden as well", async () => {
    // The ruling's measured case: `compare A and A-with-a-splitter` printed
    // `address: A` with a real balance AND said an address hidden by invisible
    // characters was never looked up and no balance may be stated for it. One
    // report, both claims, one account.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const same = await provider.get(rt, msg(`compare ${ADDR} and ${POISONED}`), undefined as never);
    expect(same.values?.xrplLookup, "setup: A really was looked up").toBe("ok");
    expect(same.text ?? "", "so it is not ALSO reported as hidden").not.toMatch(
      /addresses_hidden_by_invisible_characters/,
    );
    expect(same.data?.xrplHiddenAddresses).toBe(0);

    const other = await provider.get(
      rt,
      msg(`compare ${ADDR} and ${POISONED_PEER}`),
      undefined as never,
    );
    expect(other.text ?? "", "a DISTINCT hidden account is still stated").toMatch(
      /^ {2}addresses_hidden_by_invisible_characters: 1\b/m,
    );
  });

  it("says nothing about unreadable runs on an ordinary message", async () => {
    // The negative control. A notice that always fires satisfies every
    // assertion above and means nothing.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.text ?? "").not.toMatch(/addresses_hidden_by_invisible_characters/);
    expect(r.data?.xrplHiddenAddresses).toBe(0);
  });

  it("a message with no address AND no poisoned run is still SILENT", async () => {
    // Silence is still permitted in exactly one case, and widening the refusal
    // to every message would pollute every prompt in the agent.
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg("what is the weather like today"), undefined as never);
    expect((r.text ?? "").trim()).toBe("");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("charges no rate-limit budget, so one pasted splitter cannot silence real lookups", async () => {
    // The denial-of-service half. Nothing is charged until every check has
    // passed, so a flood of poisoned runs must leave the window untouched.
    const fetchImpl = fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK });
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    for (let i = 0; i < BOUNDS.RATE_LIMIT_MAX_REQUESTS + 2; i++) {
      const r = await provider.get(rt, msg(`look at ${POISONED}`), undefined as never);
      expect(r.values?.xrplRefusalCode, `poisoned turn ${i}`).toBe("NO_READABLE_ADDRESS");
    }
    const real = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(real.values?.xrplLookup, "a real lookup must still be affordable").toBe("ok");
  });

  it("a REFUSAL carrying both omissions stays inside the report bound", async () => {
    // A refusal message IS report content, and this is the widest one this path
    // can produce: sixty further addresses, a failed checksum, and poisoned runs
    // on top. The run line is never dropped for room, so the bound has to hold
    // with it present rather than by giving it up.
    const many = manyValidAddresses(60);
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(
      rt,
      msg(`check ${BAD} then ${many.join(" ")} and ${POISONED} and ${POISONED_PEER}`),
      undefined as never,
    );
    const text = r.text ?? "";

    expect(fetchImpl, "a bad address must never reach the network").not.toHaveBeenCalled();
    expect(r.values?.xrplRefusalCode).toBe("ADDRESS_MALFORMED");
    expect(text.length, "a refusal is report content and is bounded too").toBeLessThanOrEqual(
      BOUNDS.MAX_RENDERED_CHARS,
    );
    expect(field(text, "other_addresses_not_looked_up"), "sixty plus the refused one").toBe(61);
    expect(
      field(text, "addresses_hidden_by_invisible_characters"),
      "and both hidden accounts are counted",
    ).toBe(2);
  });

  it("the OUTER CATCH claims nothing about unreadable runs, because it measured none", async () => {
    // Invariant 10's one deliberate exception, extended by exactly one field.
    // run() can throw before it has read the message at all, so this branch
    // cannot know whether the message held a run of any kind.
    const hostile = {
      content: {
        get text(): string {
          throw new Error("GETTER_SENTINEL");
        },
      },
    };
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, hostile as never, undefined as never);
    expect(r.values?.xrplRefusalCode).toBe("INTERNAL_ERROR");
    expect((r.text ?? "").trim().length, "it must still SPEAK").toBeGreaterThan(0);
    expect(r.text ?? "", "and claim nothing it never measured").not.toMatch(
      /addresses_hidden_by_invisible_characters/,
    );
    expect(r.data?.xrplHiddenAddresses, "zero, because zero is what it measured").toBe(0);
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

// F2 through the provider, which is where the hostile value actually enters.
//
// The outer catch interpolates `error.name`, and `name` is an ordinary own
// property on an Error instance, so whoever can make run() throw chooses it.
// MEASURED against the build before renderRefusal existed: a name of 200,000
// characters produced a ProviderResult.text of 200,093, fifty times
// MAX_RENDERED_CHARS, and a name carrying U+200B and U+202E put both into the
// prompt. The bound and the printable-only property live in src/core/render.ts
// now, and these are the end-to-end proofs that the provider actually uses them.
describe("a hostile error name cannot blow the report bound or smuggle invisibles", () => {
  const cp = (n: number) => String.fromCodePoint(n);

  /** A message whose text getter throws an error with the name we choose. */
  const throwingWithName = (name: string) => {
    const error = new Error("hostile");
    error.name = name;
    return {
      get content(): { text: string } {
        throw error;
      },
    } as never;
  };

  it("bounds the refusal for error names far larger than the whole report", async () => {
    for (const len of [100, 5_000, 200_000]) {
      const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
      const r = await provider.get(rt, throwingWithName("Z".repeat(len)), undefined as never);
      const text = r.text ?? "";
      expect(r.values?.xrplRefusalCode, `len=${len}`).toBe("INTERNAL_ERROR");
      expect(text.trim().length, `len=${len} must still speak`).toBeGreaterThan(0);
      expect(text.length, `len=${len} must respect the report bound`).toBeLessThanOrEqual(
        BOUNDS.MAX_RENDERED_CHARS,
      );
    }
  });

  it("POSITIVE PROPERTY: the refusal is printable ASCII, whatever the name carried", async () => {
    const name = `Zero${cp(0x200b)}Width${cp(0x202e)}Reversed${cp(0x0a)}  address: r1${cp(0xfeff)}`;
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, throwingWithName(name), undefined as never);
    const text = r.text ?? "";

    expect(r.values?.xrplRefusalCode).toBe("INTERNAL_ERROR");
    for (const line of text.split("\n")) {
      expect(line, JSON.stringify(line)).toMatch(/^[\x20-\x7E]*$/);
    }
    for (const bad of [cp(0x200b), cp(0x202e), cp(0xfeff)]) {
      expect(text, `U+${bad.codePointAt(0)?.toString(16)} must not reach the prompt`).not.toContain(
        bad,
      );
    }
    expect(text, "and it says what it removed").toMatch(/character\(s\) were removed/);
  });

  it("survives an error whose NAME GETTER THROWS, which is the catch failing itself", async () => {
    // The outer catch is invariant 1's last line of defence and it read
    // `error.name` inline. `name` is an ordinary property on an Error instance,
    // so a subclass may define it as a getter and a getter may throw. MEASURED:
    // provider.get REJECTED from inside the catch that exists to stop exactly
    // that, and a rejected provider is erased entirely by this runtime. The
    // guard against silence was itself producing silence.
    class HostileName extends Error {
      get name(): string {
        throw new Error("NAME_GETTER_SENTINEL");
      }
    }
    const hostile = {
      get content(): { text: string } {
        throw new HostileName("hostile");
      },
    } as never;

    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    // resolves() is the assertion: before the fix this REJECTED.
    const r = await provider.get(rt, hostile, undefined as never);
    expect(r.values?.xrplRefusalCode, "it must still SPEAK a refusal").toBe("INTERNAL_ERROR");
    expect((r.text ?? "").trim().length).toBeGreaterThan(0);
    expect(r.text ?? "", "and name what it could, without pretending").toContain("(unknown error)");
    expect(r.text ?? "").not.toContain("NAME_GETTER_SENTINEL");
  });

  it("survives an error whose name is not a string at all", async () => {
    const odd = new Error("hostile");
    Object.defineProperty(odd, "name", { value: 42 });
    const hostile = {
      get content(): { text: string } {
        throw odd;
      },
    } as never;
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, hostile, undefined as never);
    expect(r.values?.xrplRefusalCode).toBe("INTERNAL_ERROR");
    expect(r.text ?? "").toContain("(unknown error)");
  });

  it("still names an ordinary error type, so the filter is not eating the diagnostic", async () => {
    // The negative control for the two above. A head that removed everything
    // would satisfy both and leave the outer catch saying nothing useful.
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, throwingWithName("TypeError"), undefined as never);
    expect(r.text ?? "").toContain("(TypeError)");
    expect(r.text ?? "", "nothing was removed, so nothing is claimed").not.toMatch(
      /character\(s\) were removed/,
    );
  });
});

// F6. `xrplAddress` and `xrplBalanceDrops` had ZERO mentions across the whole
// suite and every file under checks/. MEASURED: replacing them with `""` and
// `"0"` on the success path left 470 tests green while the provider published a
// fabricated zero balance on `values`, which is the field a consumer reads when
// it does not want to parse the report text.
//
// Three refusal codes were unmentioned in the same way: LEDGER_ERROR,
// NODE_UNREACHABLE and RESPONSE_TOO_LARGE. A code nothing reads is a code that
// can be any string at all, and a consumer branching on it branches on nothing.
describe("the values a consumer reads are the ledger's own, not a fabrication", () => {
  const infoWith = (account: string, balance: string) => ({
    result: {
      account_data: {
        Account: account,
        Balance: balance,
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

  it("publishes the ADDRESS the ledger answered for, swept over two accounts", async () => {
    for (const account of [ADDR, PEER]) {
      const provider = createXrplProvider({
        fetchImpl: fetchByMethod({
          account_info: infoWith(account, "56774133566"),
          account_lines: linesFor(account),
        }) as never,
      });
      const r = await provider.get(rt, msg(`balance of ${account}`), undefined as never);
      expect(r.values?.xrplAddress, `${account} on values`).toBe(account);
      expect(r.text ?? "", "and the report agrees with it").toMatch(
        new RegExp(`^ {2}address: ${account}$`, "m"),
      );
    }
  });

  it("publishes the EXACT drops the ledger answered with, zero included", async () => {
    // "0" is the case that matters: a fabricated zero is indistinguishable from
    // a real one unless the real one is tested, and invariant 7 exists for
    // exactly this sentence.
    for (const balance of ["0", "1", "56774133566", "9".repeat(19)]) {
      const provider = createXrplProvider({
        fetchImpl: fetchByMethod({
          account_info: infoWith(ADDR, balance),
          account_lines: linesFor(ADDR),
        }) as never,
      });
      const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
      expect(r.values?.xrplBalanceDrops, `balance=${balance}`).toBe(balance);
      expect(r.text ?? "", "and the report carries the same number").toMatch(
        new RegExp(`^ {2}xrp_balance_drops: ${balance}$`, "m"),
      );
    }
  });

  it("carries no address and no balance on values when the lookup was refused", async () => {
    // The negative control. A provider that always published these would
    // satisfy both assertions above and would publish them for a failed lookup.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "actNotFound" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.values?.xrplLookup).toBe("refused");
    expect(r.values?.xrplAddress).toBeUndefined();
    expect(r.values?.xrplBalanceDrops).toBeUndefined();
  });
});

describe("every refusal code this package can produce is reachable and named", () => {
  it("LEDGER_ERROR: the node reported an error that is neither not-found nor malformed", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: { result: { status: "error", error: "internal" } },
      }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.values?.xrplRefusalCode).toBe("LEDGER_ERROR");
    expect(r.data?.code).toBe("LEDGER_ERROR");
    expect((r.text ?? "").toLowerCase()).toMatch(/refus/);
  });

  it("NODE_UNREACHABLE: the node answered with a non-200, or could not be reached", async () => {
    const http = createXrplProvider({
      fetchImpl: vi.fn(async () => new Response("{}", { status: 503 })) as never,
    });
    const a = await http.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(a.values?.xrplRefusalCode, "a non-200 is NODE_UNREACHABLE").toBe("NODE_UNREACHABLE");

    const dead = createXrplProvider({
      fetchImpl: vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }) as never,
    });
    const b = await dead.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(b.values?.xrplRefusalCode, "a network failure is too").toBe("NODE_UNREACHABLE");
    expect(b.text ?? "", "and it never becomes an internal error").not.toContain("unexpectedly");
  });

  it("RESPONSE_TOO_LARGE: at the transport, and again at the trust line list", async () => {
    const huge = createXrplProvider({
      fetchImpl: vi.fn(
        async () => new Response("x".repeat(BOUNDS.MAX_RESPONSE_BYTES + 1_000), { status: 200 }),
      ) as never,
    });
    const a = await huge.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(a.values?.xrplRefusalCode, "a body over the byte cap").toBe("RESPONSE_TOO_LARGE");

    const manyLines = createXrplProvider({
      fetchImpl: fetchByMethod({
        account_info: ACCOUNT_INFO_OK,
        account_lines: {
          result: {
            account: ADDR,
            lines: Array.from({ length: BOUNDS.LINES_PER_PAGE * 4 + 1 }, () => ({
              account: PEER,
              balance: "1",
              currency: "USD",
              limit: "2",
            })),
            ledger_index: 106661700,
            validated: true,
            status: "success",
          },
        },
      }) as never,
    });
    const b = await manyLines.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(b.values?.xrplRefusalCode, "more lines in one page than the plugin accepts").toBe(
      "RESPONSE_TOO_LARGE",
    );
  });

  it("does NOT return one of those codes on a healthy lookup", async () => {
    // The negative control for the three above.
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.values?.xrplRefusalCode).toBeUndefined();
    expect(r.values?.xrplLookup).toBe("ok");
  });
});

describe("the checksum cap is reached, and the provider says so", () => {
  const CAP = BOUNDS.MAX_ADDRESS_CHECKSUMS_PER_MESSAGE;
  const ZWSP = "\u200B";
  const poison = (a: string) => `${a.slice(0, 24)}${ZWSP}${a.slice(24)}`;

  it("a message hiding more addresses than the budget SPEAKS the cap", async () => {
    const built = manyValidAddresses(CAP + 5);
    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(
      rt,
      msg(built.map((a) => poison(a)).join(" ")),
      undefined as never,
    );
    const text = r.text ?? "";

    expect(fetchImpl, "nothing is charged before every check has passed").not.toHaveBeenCalled();
    expect(r.values?.xrplRefusalCode).toBe("NO_READABLE_ADDRESS");
    expect(text, "the cap is spoken").toContain(`address_checks_capped: ${CAP}`);
    expect(r.data?.xrplAddressChecksCapped).toBe(true);
    expect(r.data?.xrplHiddenAddresses, "and the count it did reach is a floor").toBe(CAP);
    expect(text.length, "and the refusal is still bounded").toBeLessThanOrEqual(
      BOUNDS.MAX_RENDERED_CHARS,
    );
  });

  it("does NOT speak the cap on an ordinary message", async () => {
    const provider = createXrplProvider({
      fetchImpl: fetchByMethod({ account_info: ACCOUNT_INFO_OK, account_lines: LINES_OK }) as never,
    });
    const r = await provider.get(rt, msg(`balance of ${ADDR}`), undefined as never);
    expect(r.text ?? "").not.toMatch(/address_checks_capped/);
    expect(r.data?.xrplAddressChecksCapped).toBe(false);
  });
});

// KNOWN GAP, recorded because SECURITY required it in the shipped record rather
// than left for a later pass to rediscover as new.
//
// A run that is BOTH poisoned AND mistyped now says NOTHING. Before the
// checksum gate it was counted. The gate is what stopped the scanner firing on
// "rechtsbijstandsverzekering", and the same test that rejects a phantom
// rejects a genuine typo carrying an invisible character.
//
// The asymmetry is real and accepted: the CLEAN path still speaks about
// address-shaped strings that fail validation, through
// other_addresses_not_valid, because those became candidates and this one never
// does.
describe("KNOWN GAP: a hidden address that is ALSO mistyped says nothing", () => {
  it("is silent for a poisoned run whose visible characters fail the checksum", async () => {
    const broken = `${ADDR.slice(0, -1)}${ADDR.at(-1) === "h" ? "j" : "h"}`;
    expect(validateXrplAddress(broken).ok, "setup: it must really fail").toBe(false);
    const poisoned = `${broken.slice(0, 20)}\u200B${broken.slice(20)}`;

    const fetchImpl = vi.fn();
    const provider = createXrplProvider({ fetchImpl: fetchImpl as never });
    const r = await provider.get(rt, msg(`send to ${poisoned}`), undefined as never);
    expect((r.text ?? "").trim(), "measured: total silence").toBe("");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("the CLEAN form of the same typo is still spoken, which is the asymmetry", async () => {
    // The other half, so the gap is bounded rather than open-ended. Without the
    // splitter the string becomes a candidate, and a candidate that fails
    // validation is counted out loud.
    const broken = `${ADDR.slice(0, -1)}${ADDR.at(-1) === "h" ? "j" : "h"}`;
    const provider = createXrplProvider({ fetchImpl: vi.fn() as never });
    const r = await provider.get(rt, msg(`send to ${broken}`), undefined as never);
    expect((r.text ?? "").toLowerCase(), "it speaks").toMatch(/refus/);
    expect(r.values?.xrplRefusalCode).toBe("ADDRESS_MALFORMED");
    expect(r.text ?? "", "and never quotes it").not.toContain(broken);
  });
});
