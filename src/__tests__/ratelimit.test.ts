// V-005 requires a rate limit on anything with a network surface. H-2 is the
// reason it matters here: a ledger read costs zero drops on chain and real
// tokens off it, and the address is supplied by whoever is talking to the agent.
//
// The limiter is a pure function over a timestamp list so it can be tested at
// its boundaries without a clock. Transport owns the list; core owns the
// decision.
//
// Written before src/core/ratelimit.ts exists.

import { describe, expect, it } from "vitest";
import { BOUNDS } from "../core/bounds.ts";
import { checkRateLimit, pruneWindow } from "../core/ratelimit.ts";

const N = BOUNDS.RATE_LIMIT_MAX_REQUESTS;
const W = BOUNDS.RATE_LIMIT_WINDOW_MS;

describe("checkRateLimit", () => {
  it("allows the first request against an empty history", () => {
    expect(checkRateLimit([], 1_000).ok).toBe(true);
  });

  it("allows exactly up to the cap", () => {
    // Boundary: at the cap, not over it.
    const stamps = Array.from({ length: N - 1 }, (_, i) => 1_000 + i);
    expect(checkRateLimit(stamps, 1_000 + N).ok).toBe(true);
  });

  it("REFUSES the request that would exceed the cap", () => {
    const stamps = Array.from({ length: N }, (_, i) => 1_000 + i);
    const r = checkRateLimit(stamps, 1_000 + N);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("RATE_LIMITED");
      expect(r.message.trim().length).toBeGreaterThan(0);
    }
  });

  it("lets requests through again once the window has passed", () => {
    const stamps = Array.from({ length: N }, (_, i) => 1_000 + i);
    expect(checkRateLimit(stamps, 1_000 + W + 1).ok).toBe(true);
  });

  it("counts only timestamps inside the window", () => {
    const old = Array.from({ length: 100 }, (_, i) => i); // long expired
    expect(checkRateLimit(old, 10 * W).ok).toBe(true);
  });

  it("treats a timestamp exactly at the window edge as expired", () => {
    // Documented boundary rather than an accident: now - W is outside.
    const stamps = Array.from({ length: N }, () => 0);
    expect(checkRateLimit(stamps, W).ok).toBe(true);
    expect(checkRateLimit(stamps, W - 1).ok).toBe(false);
  });

  it("REFUSES rather than allowing when the history is not an array", () => {
    // Fail closed on the unknown. A limiter that allows on malformed state is
    // a limiter an attacker turns off by corrupting the state.
    for (const bad of [null, undefined, 42, {}, "stamps"]) {
      const r = checkRateLimit(bad as unknown as number[], 1_000);
      expect(r.ok, `${String(bad)} must refuse`).toBe(false);
    }
  });

  it("REFUSES when the history contains non-numeric entries", () => {
    const r = checkRateLimit([1, 2, "3" as unknown as number, 4], 5);
    expect(r.ok).toBe(false);
  });

  it("REFUSES when now is not a finite number", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, "now", null, undefined]) {
      expect(checkRateLimit([], bad as unknown as number).ok, `${String(bad)}`).toBe(false);
    }
  });

  it("does not mutate the caller's array", () => {
    // An aliased mutable input is one of the failure classes the mutation
    // harness seeds from.
    const stamps = [1, 2, 3];
    const copy = [...stamps];
    checkRateLimit(stamps, 10);
    expect(stamps).toEqual(copy);
  });
});

describe("pruneWindow", () => {
  it("drops expired timestamps and keeps live ones", () => {
    const out = pruneWindow([0, 1, 5_000, 59_999, 60_000], 60_000);
    expect(out).not.toContain(0);
    expect(out).toContain(60_000);
  });

  it("returns a new array rather than editing in place", () => {
    const stamps = [1, 2, 3];
    const out = pruneWindow(stamps, 10);
    expect(out).not.toBe(stamps);
    expect(stamps).toEqual([1, 2, 3]);
  });

  it("returns an empty array for malformed history rather than throwing", () => {
    for (const bad of [null, undefined, 42, {}]) {
      expect(Array.isArray(pruneWindow(bad as unknown as number[], 1))).toBe(true);
    }
  });

  it("is bounded, so a hostile caller cannot grow the history without limit", () => {
    const huge = Array.from({ length: 100_000 }, () => 1_000);
    const out = pruneWindow(huge, 1_001);
    expect(out.length).toBeLessThanOrEqual(BOUNDS.RATE_LIMIT_MAX_REQUESTS * 2);
  });
});
