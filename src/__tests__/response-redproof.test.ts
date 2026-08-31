// Added after an adversarial red-proof confirmed twelve mutations to
// response.ts that response.test.ts could not see.
//
// One structural cause behind nearly all of them: that suite validates against
// two frozen fixtures and varies a single key at a time. So a guard could be
// gated on an incidental property of those fixtures, or loosened to a form that
// still happened to reject the exact two values supplied, and stay green.
//
// A guard pinned by one value is pinned by nothing.

import { describe, expect, it } from "vitest";
import { validateAccountInfoResponse } from "../core/response.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

const okBody = () => ({
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
});

const errBody = (error: string) => ({
  result: {
    error,
    error_code: 19,
    error_message: "Account not found.",
    ledger_index: 106661700,
    status: "error",
  },
});

describe("the validated-ledger flag, pinned against absence and against junk", () => {
  it("REFUSES when the validated key is genuinely ABSENT, not merely undefined", () => {
    // The confirmed hole. Setting `validated = undefined` CREATES an own
    // property whose value is undefined, so a guard rewritten as "only enforce
    // the flag when the node supplied one" still refused that fixture and the
    // suite stayed green, while a real response omitting the key entirely
    // sailed through and was reported as validated ledger fact.
    const body = okBody() as Record<string, any>;
    delete body.result.validated;
    expect(Object.hasOwn(body.result, "validated")).toBe(false);
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("RESPONSE_MALFORMED");
  });

  it("REFUSES any truthy non-boolean in place of true", () => {
    // The guard's comment says strict equality with true. The original suite
    // only ever supplied false and undefined, both falsy, so a truthiness check
    // passed every assertion while accepting any junk as the node's
    // confirmation that the ledger was validated.
    for (const junk of ["true", "yes", 1, {}, [], "false", -1]) {
      const body = okBody() as Record<string, any>;
      body.result.validated = junk;
      expect(
        validateAccountInfoResponse(body, ADDR).ok,
        `validated=${JSON.stringify(junk)} must be refused`,
      ).toBe(false);
    }
  });

  it("REFUSES a validated flag supplied only by the prototype", () => {
    const body = okBody() as Record<string, any>;
    const polluted: Record<string, unknown> = Object.create({ validated: true });
    for (const [k, v] of Object.entries(body.result)) {
      if (k !== "validated") polluted[k] = v;
    }
    body.result = polluted;
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("does not accept an unrelated envelope field as a substitute", () => {
    // A confirmed hole gated the refusal on ledger_hash being absent, invisible
    // because neither fixture carried that key.
    const body = okBody() as Record<string, any>;
    body.result.validated = false;
    body.result.ledger_hash = "A".repeat(64);
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });
});

describe("the status check refuses on its own, not only via the error branch", () => {
  it("REFUSES a non-success status carrying NO error string", () => {
    // Confirmed hole: deleting the status catch-all entirely stayed green,
    // because every error fixture in the suite also carried a string `error`,
    // which the branch above already handles. Nothing pinned the catch-all.
    const body = okBody() as Record<string, any>;
    body.result.status = "error";
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok, "a self-declared failure with no error string must still refuse").toBe(false);
  });

  it("REFUSES a status that merely CONTAINS the word success", () => {
    for (const status of ["unsuccessful", "not-success", "success-failed", "SUCCESS"]) {
      const body = okBody() as Record<string, any>;
      body.result.status = status;
      expect(validateAccountInfoResponse(body, ADDR).ok, `status=${status}`).toBe(false);
    }
  });

  it("REFUSES a missing status", () => {
    const body = okBody() as Record<string, any>;
    delete body.result.status;
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });
});

describe("not-found never reads as a zero balance", () => {
  it("the refusal message contains nothing that looks like a balance", () => {
    // Confirmed hole: nothing pinned the CONTENT of this message, so it could be
    // rewritten to state a 0.000000 XRP balance and stay green. That is the exact
    // failure the module exists to prevent, restated as text.
    const r = validateAccountInfoResponse(errBody("actNotFound"), ADDR);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("ACCOUNT_NOT_FOUND");
      const m = r.message.toLowerCase();
      expect(m).not.toContain("0.000000");
      expect(m).not.toMatch(/\b0 xrp\b/);
      expect(m).not.toMatch(/holds 0\b/);
      expect(m).not.toMatch(/balance of 0/);
      // It must positively say the account is absent.
      expect(m).toMatch(/does not exist|no record|not found/);
    }
  });

  it("still reports not-found when the envelope carries a validated flag", () => {
    // Confirmed hole gated the not-found branch on validated !== true, invisible
    // because the hand-written error fixture omitted the flag entirely.
    const body = errBody("actNotFound") as Record<string, any>;
    body.result.validated = true;
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("ACCOUNT_NOT_FOUND");
  });
});

describe("the balance is bounded and is never substituted", () => {
  it("REFUSES a balance longer than the ledger can produce", () => {
    // Total XRP supply is 1e17 drops, 18 digits. A 50,000-digit Balance passed
    // validation, was rendered, and the report's own size cap then truncated the
    // result, so the balance crowded out every other field including the
    // truncation notice. The cap held and the report became useless.
    const body = okBody() as Record<string, any>;
    body.result.account_data.Balance = "9".repeat(50_000);
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("accepts a balance at the realistic maximum", () => {
    // The negative control for that bound: it must not reject real data.
    const body = okBody() as Record<string, any>;
    body.result.account_data.Balance = "100000000000000000";
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.balanceDrops).toBe("100000000000000000");
  });

  it("does not accept a lowercase decoy in place of Balance", () => {
    // Confirmed hole: a `?? own(accountData, "balance")` fallback let a response
    // with NO Balance key but a lowercase decoy be reported as a real balance.
    const body = okBody() as Record<string, any>;
    delete body.result.account_data.Balance;
    body.result.account_data.balance = "0";
    expect(validateAccountInfoResponse(body, ADDR).ok).toBe(false);
  });

  it("returns the balance byte-for-byte, never a truncation of it", () => {
    // Confirmed hole: slicing balanceDrops understated a real balance by three
    // orders of magnitude while the suite stayed green.
    const exact = "56774133566";
    const body = okBody() as Record<string, any>;
    body.result.account_data.Balance = exact;
    const r = validateAccountInfoResponse(body, ADDR);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.balanceDrops).toBe(exact);
      expect(r.value.balanceDrops).toHaveLength(exact.length);
    }
  });
});
