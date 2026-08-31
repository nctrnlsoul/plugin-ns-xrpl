// Rows 2, 3 and 4 of the fail-closed table, and finding M-5.
//
//   row 2  "Account exists on ledger -> REPORT NOT FOUND explicitly.
//           Never render as zero balance."
//   row 4  "Node response shape recognised -> REFUSE. This is M-5, and it is
//           the one most likely to be got wrong."
//
// M-5's failure shape, written out in the security pass:
//     balance = (response or {}).get("account_data", {}).get("Balance", 0)
// Every fallback fires and the plugin reports "this account holds 0 XRP" with
// total confidence. For a plugin whose only job is reporting, a confidently
// wrong report IS the failure.
//
// These validators take the RAW body. Nothing shapes it first. If Transport
// shaped it, Core's guard could never fire.
//
// Written before src/core/response.ts exists.
//
// Every fixture below is the real shape captured from https://xrplcluster.com/
// (rippled 3.3.0) on 2026-08-31, not a shape written from memory.

import { describe, expect, it } from "vitest";
import { validateAccountInfoResponse, validateAccountLinesResponse } from "../core/response.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

// Verbatim shape from the live node.
const REAL_ACCOUNT_INFO = {
  result: {
    account_data: {
      Account: ADDR,
      Balance: "56774133566",
      Flags: 8060928,
      LedgerEntryType: "AccountRoot",
      OwnerCount: 0,
      PreviousTxnID: "E".repeat(64),
      PreviousTxnLgrSeq: 106661000,
      RegularKey: "rrrrrrrrrrrrrrrrrrrrBZbvji",
      Sequence: 4,
      TransferRate: 1002000000,
      index: "A".repeat(64),
    },
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

// Verbatim error shape. Note the HTTP status was 200.
const REAL_ERROR = (error: string) => ({
  result: {
    error,
    error_code: 35,
    error_message: "Account malformed.",
    ledger_hash: "A".repeat(64),
    ledger_index: 106661700,
    request: { account: ADDR, command: "account_info", ledger_index: "validated" },
    status: "error",
  },
});

describe("validateAccountInfoResponse", () => {
  it("accepts the real success shape and returns the balance as the node sent it", () => {
    const r = validateAccountInfoResponse(REAL_ACCOUNT_INFO, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.balanceDrops).toBe("56774133566");
      expect(r.value.address).toBe(ADDR);
      expect(r.value.ledgerIndex).toBe(106661700);
    }
  });

  it("REFUSES a body whose result.status is error even though HTTP was 200", () => {
    // The trap. rippled answers 200 OK and puts the failure in the body, so
    // `if (!res.ok) throw` sees a healthy response and proceeds.
    const r = validateAccountInfoResponse(REAL_ERROR("actMalformed"), ADDR);
    expect(r.ok).toBe(false);
  });

  it("reports actNotFound as ACCOUNT_NOT_FOUND, never as a zero balance", () => {
    // Row 2. The whole point: an unfunded account and a funded account holding
    // nothing must not produce the same sentence.
    const r = validateAccountInfoResponse(REAL_ERROR("actNotFound"), ADDR);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("ACCOUNT_NOT_FOUND");
      expect(r.message).not.toMatch(/\b0 XRP\b/);
      expect(r.message.toLowerCase()).toContain("not");
    }
  });

  it("REFUSES rather than defaulting when Balance is missing", () => {
    // The `.get("Balance", 0)` shape. There is no correct default here.
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.account_data.Balance = undefined;
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("RESPONSE_MALFORMED");
  });

  it("REFUSES when account_data is missing entirely", () => {
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.account_data = undefined;
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("REFUSES a Balance that is a number rather than a drops string", () => {
    // Type confusion. 56774133566 as a JS number is still exact here, but the
    // moment a balance exceeds 2^53 drops a silent precision loss becomes a
    // wrong balance. The node sends a string; anything else is not the node
    // this code was written against.
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.account_data.Balance = 56774133566;
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("REFUSES a Balance string that is not a run of digits", () => {
    for (const bad of ["", " ", "abc", "1e10", "-100", "1.5", "0x10", "56774133566 "]) {
      const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
      body.result.account_data.Balance = bad;
      expect(
        validateAccountInfoResponse(body, ADDR).ok,
        `Balance ${JSON.stringify(bad)} must be refused`,
      ).toBe(false);
    }
  });

  it("accepts a genuine zero balance and does NOT confuse it with absence", () => {
    // The mirror of the fail-open. A real "0" is real data and must survive.
    // Never fold a real false into a fallback.
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.account_data.Balance = "0";
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.balanceDrops).toBe("0");
  });

  it("REFUSES when the node answers about a different account than was asked", () => {
    // A response/request mismatch is either a bug or an attack, and either way
    // reporting it as the answer to the question asked is wrong.
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.account_data.Account = "rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B";
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(false);
  });

  it("REFUSES unvalidated ledger data", () => {
    // validated:false means the node is reporting a ledger that can still
    // change. Reporting it as fact is reporting a guess.
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.validated = false;
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("REFUSES a missing validated flag rather than assuming true", () => {
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    body.result.validated = undefined;
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("REFUSES every non-object body without throwing", () => {
    for (const bad of [null, undefined, 42, "", "ok", [], true, () => {}, Number.NaN]) {
      const r = validateAccountInfoResponse(bad as unknown, ADDR);
      expect(r.ok, `${String(bad)} must be refused`).toBe(false);
      expect(r.ok === false && r.message.trim().length > 0).toBe(true);
    }
  });

  it("REFUSES a body with no result key", () => {
    expect(validateAccountInfoResponse({}, ADDR).ok).toBe(false);
    expect(validateAccountInfoResponse({ account_data: {} }, ADDR).ok).toBe(false);
  });

  it("does not inherit a prototype-polluted Balance", () => {
    // If a validator reads Balance off the prototype chain, a polluted global
    // Object.prototype supplies one and the guard passes on absent data.
    const body = structuredClone(REAL_ACCOUNT_INFO) as Record<string, any>;
    delete body.result.account_data.Balance;
    const polluted = Object.create({ Balance: "999999999" });
    Object.assign(polluted, body.result.account_data);
    body.result.account_data = polluted;
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(false);
  });
});

// Real account_lines shape: keys account, balance, currency, limit, limit_peer,
// quality_in, quality_out. A 10-line query returned a marker, so pagination is
// real rather than theoretical.
const REAL_LINES = {
  result: {
    account: ADDR,
    lines: [
      {
        account: "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS",
        balance: "0",
        currency: "BTC",
        limit: "5",
        limit_peer: "0",
        quality_in: 0,
        quality_out: 0,
      },
      {
        account: "rngJ9Co6MPZxJcyepRv2hMPV1HqaeGCdVU",
        balance: "-0.000068000005885",
        currency: "USD",
        limit: "0",
        limit_peer: "0",
        quality_in: 0,
        quality_out: 0,
      },
    ],
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

describe("validateAccountLinesResponse", () => {
  it("accepts the real shape and preserves balances verbatim", () => {
    const r = validateAccountLinesResponse(REAL_LINES, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.lines).toHaveLength(2);
      expect(r.value.lines[0]?.currency).toBe("BTC");
      expect(r.value.lines[1]?.balance).toBe("-0.000068000005885");
      expect(r.value.marker).toBeUndefined();
    }
  });

  it("accepts an account with genuinely zero trust lines", () => {
    const body = structuredClone(REAL_LINES) as Record<string, any>;
    body.result.lines = [];
    const r = validateAccountLinesResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.lines).toHaveLength(0);
  });

  it("REFUSES when lines is missing, rather than treating it as empty", () => {
    // "no trust lines" and "the node did not tell us" are different answers and
    // the second one must never be rendered as the first.
    const body = structuredClone(REAL_LINES) as Record<string, any>;
    body.result.lines = undefined;
    const r = validateAccountLinesResponse(body, ADDR);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("RESPONSE_MALFORMED");
  });

  it("REFUSES when lines is not an array", () => {
    for (const bad of [{}, "lines", 3, true, null]) {
      const body = structuredClone(REAL_LINES) as Record<string, any>;
      body.result.lines = bad;
      expect(validateAccountLinesResponse(body, ADDR).ok, `${String(bad)}`).toBe(false);
    }
  });

  it("accepts exponent-form balances, which the real ledger actually emits", () => {
    // MEASURED 2026-08-31: 2 of 300 trust lines on a live issuer account
    // carried balances in this form. An earlier pattern without an exponent
    // branch rejected them, and the real path refused a legitimate account.
    for (const value of [
      "-4263500000000000e-27",
      "-1534000000000000e-26",
      "1e10",
      "1.5E+20",
      "0",
      "-0.000068000005885",
    ]) {
      const body = structuredClone(REAL_LINES) as Record<string, any>;
      body.result.lines[0].balance = value;
      const r = validateAccountLinesResponse(body, ADDR);
      expect(r.ok, `${value} is real ledger data and must be accepted`).toBe(true);
      if (r.ok) expect(r.value.lines[0]?.balance).toBe(value);
    }
  });

  it("still rejects values that only look numeric", () => {
    for (const bad of [
      "1e",
      "e5",
      "--1",
      "1.2.3",
      "0x10",
      " 1",
      "1 ",
      "Infinity",
      "NaN",
      "1,000",
    ]) {
      const body = structuredClone(REAL_LINES) as Record<string, any>;
      body.result.lines[0].balance = bad;
      const r = validateAccountLinesResponse(body, ADDR);
      expect(r.ok && r.value.droppedLines === 1, `${JSON.stringify(bad)} must be dropped`).toBe(
        true,
      );
    }
  });

  it("drops an unreadable line and COUNTS it, rather than refusing everything", () => {
    // This replaces an earlier refuse-the-whole-list rule. Refuse-all let one
    // bad line erase every good one, and handed anyone able to place an odd
    // trust line a denial of service against that account's whole report.
    const body = structuredClone(REAL_LINES) as Record<string, any>;
    body.result.lines[1].currency = undefined;
    const r = validateAccountLinesResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.lines).toHaveLength(1);
      expect(r.value.droppedLines).toBe(1);
    }
  });

  it("drops a line whose counterparty is not a valid XRPL address", () => {
    const body = structuredClone(REAL_LINES) as Record<string, any>;
    body.result.lines[0].account = "not-an-address";
    const r = validateAccountLinesResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.droppedLines).toBe(1);
      expect(r.value.lines.every((l) => l.account !== "not-an-address")).toBe(true);
    }
  });

  it("reports zero dropped lines when every line is readable", () => {
    // The negative control. If droppedLines were always non-zero the count
    // would be noise rather than a signal.
    const r = validateAccountLinesResponse(REAL_LINES, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.droppedLines).toBe(0);
  });

  it("REFUSES an error body even at HTTP 200", () => {
    expect(validateAccountLinesResponse(REAL_ERROR("actNotFound"), ADDR).ok).toBe(false);
  });

  it("REFUSES unvalidated ledger data", () => {
    const body = structuredClone(REAL_LINES) as Record<string, any>;
    body.result.validated = false;
    expect(validateAccountLinesResponse(body, ADDR).ok).toBe(false);
  });

  it("surfaces a marker when the node paginates, rather than hiding it", () => {
    // If the marker is dropped, a partial list silently becomes the full list.
    const body = structuredClone(REAL_LINES) as Record<string, any>;
    body.result.marker = { ledger: 1, seq: 2 };
    const r = validateAccountLinesResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.marker).toBeDefined();
  });

  it("REFUSES every non-object body without throwing", () => {
    for (const bad of [null, undefined, 42, "", [], true]) {
      expect(validateAccountLinesResponse(bad as unknown, ADDR).ok).toBe(false);
    }
  });
});
