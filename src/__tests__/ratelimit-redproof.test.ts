// Added after an adversarial red-proof confirmed seven mutations to
// ratelimit.ts that ratelimit.test.ts could not see.
//
// The structural cause: the original tests built histories out of one uniform
// kind of timestamp (all live, or all long-expired) and corrupted at most the
// third entry. So the limiter could be rewritten to look at a prefix, to switch
// itself off when any entry had expired, or to accept non-finite numbers, and
// every existing assertion still passed.
//
// The window is the interesting part of a rate limiter, so the tests have to
// contain a mixture.

import { describe, expect, it } from "vitest";
import { BOUNDS } from "../core/bounds.ts";
import { checkRateLimit, pruneWindow } from "../core/ratelimit.ts";

const N = BOUNDS.RATE_LIMIT_MAX_REQUESTS;
const W = BOUNDS.RATE_LIMIT_WINDOW_MS;

describe("fail-closed on malformed state, whatever the malformation", () => {
  it("REFUSES a history containing NaN or Infinity", () => {
    // Confirmed hole: dropping the finiteness half of the entry check left
    // `typeof s === "number"` accepting NaN and +/-Infinity, which then vanish
    // in the live filter (every comparison against them is false), so the count
    // reads as zero and the limiter returns ok on corrupt state. It reads as a
    // simplification, not as a deletion.
    for (const junk of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const stamps = [1_000, 1_001, junk, 1_002];
      const r = checkRateLimit(stamps, 1_003);
      expect(r.ok, `${String(junk)} in the history must refuse`).toBe(false);
    }
  });

  it("REFUSES a corrupt entry no matter where it sits in the history", () => {
    // Confirmed hole: scanning only the first four entries left anything at
    // index 4 or beyond undetected. Position must not matter.
    //
    // My first attempt at this test did not close the hole. It used a 20-entry
    // history, which is over the cap of 10, so the refusal came from the CAP and
    // the corrupt entry was never the reason. The test passed while the guard it
    // named was disabled. That is rule 95 exactly: a test is usually disabled by
    // its setup, not its assertion.
    //
    // So the history must stay BELOW the cap, and the assertion must name the
    // corruption rather than accepting any refusal.
    for (const idx of [0, 1, 4, 5, 7]) {
      const size = 8; // under RATE_LIMIT_MAX_REQUESTS, so the cap cannot fire
      expect(size).toBeLessThan(N);
      const stamps: unknown[] = Array.from({ length: size }, (_, i) => 1_000 + i);
      stamps[idx] = "5";

      // Prove the setup: without the corrupt entry this history is ALLOWED.
      const clean = Array.from({ length: size }, (_, i) => 1_000 + i);
      expect(checkRateLimit(clean, 1_010).ok, "the clean control must be allowed").toBe(true);

      const r = checkRateLimit(stamps as number[], 1_010);
      expect(r.ok, `a string at index ${idx} must refuse`).toBe(false);
      if (!r.ok) {
        expect(
          r.message.toLowerCase(),
          `index ${idx}: the refusal must be about the corrupt entry, not the cap`,
        ).toContain("unreadable");
      }
    }
  });

  it("REFUSES a history whose entries are objects or null", () => {
    for (const junk of [null, undefined, {}, [], true]) {
      const stamps = [1_000, junk, 1_001] as unknown as number[];
      expect(checkRateLimit(stamps, 1_002).ok, `${String(junk)}`).toBe(false);
    }
  });
});

describe("the cap counts EVERY live request, not a convenient subset", () => {
  it("still refuses when expired entries sit alongside a full window", () => {
    // Confirmed hole: gating the cap on live.length === stamps.length meant one
    // stale timestamp anywhere switched the limiter off completely. Real
    // histories always contain expired entries, so this is the normal case.
    const expired = [0];
    const live = Array.from({ length: N }, (_, i) => 100_000 + i);
    const r = checkRateLimit([...expired, ...live], 100_010);
    expect(r.ok, "one expired stamp must not disable the limiter").toBe(false);
  });

  it("still refuses when the live entries sit past the first N of the history", () => {
    // Confirmed hole: deciding from stamps.slice(0, N) made live requests beyond
    // that prefix invisible.
    const expired = Array.from({ length: N }, (_, i) => i);
    const live = Array.from({ length: N }, (_, i) => 100_000 + i);
    const r = checkRateLimit([...expired, ...live], 100_010);
    expect(r.ok).toBe(false);
  });

  it("counts timestamps dated ahead of now", () => {
    // Confirmed hole: adding `s <= now` to the live filter made future-dated
    // entries stop counting. isLive has no upper bound by design, and a clock
    // that jumps backwards is not a reason to stop rate limiting.
    const future = Array.from({ length: N }, (_, i) => 2_000 + i);
    expect(checkRateLimit(future, 1_500).ok).toBe(false);
  });

  it("allows again once the whole window has genuinely rolled over", () => {
    // The negative control for all three above: the limiter must still open.
    const stamps = Array.from({ length: N }, (_, i) => 1_000 + i);
    expect(checkRateLimit(stamps, 1_000 + W + 1).ok).toBe(true);
  });
});

describe("pruneWindow keeps the entries that will still matter", () => {
  it("retains the NEWEST timestamps, not the oldest", () => {
    // Confirmed hole: slicing from the front kept the oldest 20, which are
    // exactly the ones about to expire, so the limiter forgot the recent
    // requests that will still be inside the window on the next check.
    const stamps = Array.from({ length: 30 }, (_, i) => i);
    const kept = pruneWindow(stamps, 30);
    expect(kept.length).toBeLessThanOrEqual(N * 2);
    expect(Math.max(...kept), "the newest timestamp must survive").toBe(29);
    expect(kept).not.toContain(0);
  });

  it("a pruned history still refuses at the cap", () => {
    // The property that actually matters, end to end: pruning must not lose
    // enough recent entries to reopen the limiter.
    let stamps: number[] = [];
    const now = 1_000_000;
    for (let i = 0; i < N; i++) stamps = pruneWindow([...stamps, now + i], now + i);
    expect(checkRateLimit(stamps, now + N).ok, "the cap must survive pruning").toBe(false);
  });
});
