// The in-turn cache, tested where the decisions actually live.
//
// Written before src/core/turncache.ts exists, and every predicate it names is
// exported for the same reason checkRateLimit and pruneWindow are: src/core/
// response.ts and src/core/node-url.ts each record a validator that sat inside a
// closure where no test could reach it, and both stopped working quietly.
//
// The rules from CLAUDE.md that shape this file:
//   - a negative test must fail for the REASON it names, so every rejection
//     asserts null (or a miss) from the branch under test rather than "not the
//     happy path".
//   - test the threshold. The smallest cache that must evict is one entry over
//     the bound, not a comfortable hundred.
//   - assert the positive property. "The key changed" is weaker than "the key
//     changed AND the component that changed is the only difference".

import { describe, expect, it } from "vitest";
import { BOUNDS } from "../core/bounds.ts";
import {
  type CachedResult,
  createTurnCache,
  isUuidLike,
  readTurnCache,
  TURN_CACHE_KEY_SEPARATOR,
  turnCacheKey,
  writeTurnCache,
} from "../core/turncache.ts";

const AGENT = "11111111-2222-4333-8444-555555555555";
const MESSAGE = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";

const GOOD = { agentId: AGENT, messageId: MESSAGE, address: ADDR, skipped: 0, now: 1_000 };

function result(text: string): CachedResult {
  return { text, values: { xrplLookup: "ok" }, data: { ok: true, xrplCache: "miss" } };
}

describe("the TTL is a relationship, not a number", () => {
  it("is at least the whole lookup budget, which is a MARGIN and not a derivation", () => {
    // Asserting the literal 30_000 would pin the value and not the property, so
    // the relationship is what is pinned. What the relationship MEANS changed,
    // and this comment has to change with it or it outlives the behaviour it
    // describes.
    //
    // It used to be a derivation: the entry was stamped before the network read,
    // so a lookup that spent its whole budget wrote an entry already
    // TOTAL_LOOKUP_BUDGET_MS old. That is no longer true. The stamp is taken at
    // WRITE time now, proved by "the TTL runs from the WRITE" in
    // provider-cache.test.ts, so network time is not charged against the TTL.
    //
    // What the TTL has to cover is the gap between the WRITE of the first ask
    // and the READ of the second, and that gap is a stage-1 model generation
    // inside the host. Nothing here bounds it or can measure it. The budget is
    // used as the UNIT because it is the largest interval this package controls,
    // not because it is the interval being covered.
    expect(BOUNDS.TURN_CACHE_TTL_MS).toBeGreaterThanOrEqual(BOUNDS.TOTAL_LOOKUP_BUDGET_MS);
  });

  it("stays under the runtime's own silent cutoff, so an entry cannot outlive its turn", () => {
    expect(BOUNDS.TURN_CACHE_TTL_MS).toBeLessThanOrEqual(30_000);
  });

  it("bounds the entries it keeps, and the worst case is arithmetic", () => {
    expect(BOUNDS.TURN_CACHE_MAX_ENTRIES).toBeGreaterThan(0);
    // 64 x 4,000 characters is roughly 256 KB per process. If either number
    // moves, the sentence in bounds.ts naming that figure has to move with it.
    expect(BOUNDS.TURN_CACHE_MAX_ENTRIES * BOUNDS.MAX_RENDERED_CHARS).toBeLessThanOrEqual(400_000);
  });
});

describe("the UUID shape is checked, not assumed", () => {
  it("accepts a real UUID in either case", () => {
    expect(isUuidLike(AGENT)).toBe(true);
    expect(isUuidLike(AGENT.toUpperCase())).toBe(true);
  });

  it("REJECTS absence, the wrong type, and a string that merely looks close", () => {
    // Absence and a non-UUID string are both real inputs: Memory.id is declared
    // `id?: UUID` and UUID is an unbranded string.
    for (const bad of [
      undefined,
      null,
      42,
      "",
      "undefined",
      "not-a-uuid",
      `${AGENT}x`,
      AGENT.slice(0, -1),
      `${AGENT.slice(0, 8)}_${AGENT.slice(9)}`,
    ]) {
      expect(isUuidLike(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});

describe("the key admits only what it can safely partition on", () => {
  it("builds a key from a complete, well-formed input", () => {
    expect(turnCacheKey(GOOD)).toBe([AGENT, MESSAGE, ADDR, "0"].join(TURN_CACHE_KEY_SEPARATOR));
  });

  it("separates components with a byte none of them can contain", () => {
    // Not decoration. Without a separator no component can forge, two different
    // (agent, message) pairs can concatenate to one string. NUL cannot appear in
    // a UUID, in Ripple base58, or in a decimal integer.
    expect(TURN_CACHE_KEY_SEPARATOR).toBe(String.fromCharCode(0));
    expect(AGENT.includes(TURN_CACHE_KEY_SEPARATOR)).toBe(false);
    expect(ADDR.includes(TURN_CACHE_KEY_SEPARATOR)).toBe(false);
  });

  it("REFUSES a missing message id rather than keying on the string undefined", () => {
    // A template literal would turn an absent id into "undefined" and give every
    // id-less message in the process one shared partition.
    expect(turnCacheKey({ ...GOOD, messageId: undefined })).toBeNull();
    expect(turnCacheKey({ ...GOOD, messageId: null })).toBeNull();
  });

  it("REFUSES a message id that is a string but not a UUID", () => {
    expect(turnCacheKey({ ...GOOD, messageId: "undefined" })).toBeNull();
    expect(turnCacheKey({ ...GOOD, messageId: "not-a-uuid" })).toBeNull();
  });

  it("REFUSES a missing or malformed agent id", () => {
    expect(turnCacheKey({ ...GOOD, agentId: undefined })).toBeNull();
    expect(turnCacheKey({ ...GOOD, agentId: "not-a-uuid" })).toBeNull();
  });

  it("REFUSES an absent or empty address", () => {
    expect(turnCacheKey({ ...GOOD, address: undefined })).toBeNull();
    expect(turnCacheKey({ ...GOOD, address: "" })).toBeNull();
  });

  it("REFUSES a skipped count that is not a whole number at or above zero", () => {
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "1", undefined]) {
      expect(turnCacheKey({ ...GOOD, skipped: bad }), String(bad)).toBeNull();
    }
  });

  it("REFUSES a non-finite clock, so a corrupt clock cannot partition anything", () => {
    // The rate limiter fails CLOSED on a non-finite clock. A key built on one
    // would put a cache read in front of a limiter that would have refused.
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, "1000"]) {
      expect(turnCacheKey({ ...GOOD, now: bad }), String(bad)).toBeNull();
    }
  });

  it("carries the AGENT, so two agents never read each other's entry", () => {
    const other = turnCacheKey({ ...GOOD, agentId: "99999999-8888-4777-8666-555555555555" });
    expect(other).not.toBeNull();
    expect(other).not.toBe(turnCacheKey(GOOD));
  });

  it("carries the MESSAGE, so two turns never share an entry", () => {
    const other = turnCacheKey({ ...GOOD, messageId: "99999999-8888-4777-8666-555555555555" });
    expect(other).not.toBe(turnCacheKey(GOOD));
  });

  it("carries the ADDRESS", () => {
    expect(turnCacheKey({ ...GOOD, address: "rrrrrrrrrrrrrrrrrrrrrhoLvTp" })).not.toBe(
      turnCacheKey(GOOD),
    );
  });

  it("THRESHOLD: carries the skipped count, and one is enough to change the key", () => {
    // The report text differs by exactly the other_addresses_not_looked_up line
    // when this count differs, and rule 10 says that omission is always spoken.
    // A key that drops it serves a report missing the notice.
    expect(turnCacheKey({ ...GOOD, skipped: 1 })).not.toBe(turnCacheKey({ ...GOOD, skipped: 0 }));
  });

  it("is stable: the same input twice is the same key", () => {
    expect(turnCacheKey(GOOD)).toBe(turnCacheKey({ ...GOOD, now: GOOD.now + 5 }));
  });
});

describe("reading is a decision, and every unknown means miss", () => {
  it("serves an entry stored inside the TTL", () => {
    const cache = createTurnCache();
    const key = turnCacheKey(GOOD);
    writeTurnCache(cache, key, result("report"), 1_000);
    expect(readTurnCache(cache, key, 1_000)?.text).toBe("report");
    expect(readTurnCache(cache, key, 1_000 + BOUNDS.TURN_CACHE_TTL_MS)?.text).toBe("report");
  });

  it("THRESHOLD: one millisecond past the TTL is a MISS, and the entry is dropped", () => {
    const cache = createTurnCache();
    const key = turnCacheKey(GOOD);
    writeTurnCache(cache, key, result("report"), 1_000);
    expect(readTurnCache(cache, key, 1_001 + BOUNDS.TURN_CACHE_TTL_MS)).toBeNull();
    expect(cache.size, "a stale entry is deleted, not merely skipped").toBe(0);
  });

  it("REFUSES an entry whose age is NEGATIVE, so a future stamp is not immortal", () => {
    // The one-sided form `age <= TTL` is true for every negative age, which makes
    // an entry written under a clock that later runs backwards permanently
    // fresh. deps.now() is injectable, so that clock is reachable.
    const cache = createTurnCache();
    const key = turnCacheKey(GOOD);
    writeTurnCache(cache, key, result("report"), 10_000);
    expect(readTurnCache(cache, key, 9_999)).toBeNull();
    expect(cache.size).toBe(0);
  });

  it("misses on a null key without touching the map", () => {
    const cache = createTurnCache();
    writeTurnCache(cache, turnCacheKey(GOOD), result("report"), 1_000);
    expect(readTurnCache(cache, null, 1_000)).toBeNull();
    expect(cache.size, "a null key must not evict anything either").toBe(1);
  });

  it("misses on a key that was never written", () => {
    const cache = createTurnCache();
    expect(readTurnCache(cache, turnCacheKey(GOOD), 1_000)).toBeNull();
  });

  it("REFUSES a poisoned entry: not an object, no text, or a non-finite stamp", () => {
    const key = "k";
    for (const poison of [
      "not an object",
      42,
      null,
      { storedAt: 1_000, values: {}, data: {} },
      { storedAt: 1_000, text: 7, values: {}, data: {} },
      { storedAt: Number.NaN, text: "x", values: {}, data: {} },
      { storedAt: "1000", text: "x", values: {}, data: {} },
      { storedAt: 1_000, text: "x", values: null, data: {} },
      { storedAt: 1_000, text: "x", values: {}, data: null },
    ]) {
      const cache = createTurnCache();
      cache.set(key, poison as never);
      expect(readTurnCache(cache, key, 1_000), JSON.stringify(poison)).toBeNull();
      expect(cache.size, `${JSON.stringify(poison)} must be deleted`).toBe(0);
    }
  });

  it("returns a FRESH object, so a consumer that mutates it cannot poison a later hit", () => {
    const cache = createTurnCache();
    const key = turnCacheKey(GOOD);
    writeTurnCache(cache, key, result("report"), 1_000);

    const first = readTurnCache(cache, key, 1_000);
    expect(first).not.toBeNull();
    (first?.values as Record<string, string>).xrplLookup = "POISONED";
    (first?.data as Record<string, string>).ok = "POISONED";

    const second = readTurnCache(cache, key, 1_000);
    expect(second?.values.xrplLookup, "the stored entry must be untouched").toBe("ok");
    expect(second?.data.ok).toBe(true);
  });

  it("does not share the object it was HANDED either", () => {
    const cache = createTurnCache();
    const key = turnCacheKey(GOOD);
    const stored = { text: "report", values: { xrplLookup: "ok" }, data: { ok: true } };
    writeTurnCache(cache, key, stored, 1_000);
    stored.values.xrplLookup = "POISONED";
    expect(readTurnCache(cache, key, 1_000)?.values.xrplLookup).toBe("ok");
  });
});

describe("the map is bounded, and the bound is enforced where it grows", () => {
  const keyFor = (n: number) => `key-${n}`;

  it("THRESHOLD: one entry over the bound evicts exactly one, and the OLDEST", () => {
    const cache = createTurnCache();
    for (let i = 0; i < BOUNDS.TURN_CACHE_MAX_ENTRIES; i++) {
      writeTurnCache(cache, keyFor(i), result(`r${i}`), 1_000);
    }
    expect(cache.size).toBe(BOUNDS.TURN_CACHE_MAX_ENTRIES);

    writeTurnCache(cache, keyFor(BOUNDS.TURN_CACHE_MAX_ENTRIES), result("newest"), 1_000);
    expect(cache.size).toBe(BOUNDS.TURN_CACHE_MAX_ENTRIES);
    expect(readTurnCache(cache, keyFor(0), 1_000), "the oldest key is the one dropped").toBeNull();
    expect(readTurnCache(cache, keyFor(BOUNDS.TURN_CACHE_MAX_ENTRIES), 1_000)?.text).toBe("newest");
  });

  it("stays bounded through a burst of writes with NO reads in between", () => {
    // The bound has to be enforced on insert, because insert is the only path
    // that grows the map. Enforcing it on read leaves a write-only burst
    // unbounded, and a write-only burst is exactly what a flood of turns is.
    const cache = createTurnCache();
    for (let i = 0; i < BOUNDS.TURN_CACHE_MAX_ENTRIES * 3; i++) {
      writeTurnCache(cache, keyFor(i), result(`r${i}`), 1_000);
    }
    expect(cache.size).toBeLessThanOrEqual(BOUNDS.TURN_CACHE_MAX_ENTRIES);
  });

  it("sweeps entries that expired, before it starts dropping live ones", () => {
    const cache = createTurnCache();
    writeTurnCache(cache, "old", result("old"), 1_000);
    writeTurnCache(cache, "new", result("new"), 1_000 + BOUNDS.TURN_CACHE_TTL_MS + 1);
    expect(cache.has("old"), "the expired entry is swept on the next insert").toBe(false);
    expect(cache.size).toBe(1);
  });

  it("THRESHOLD: a refused write leaves ONE existing live entry exactly as it was", () => {
    // This test used to write into an EMPTY cache and assert the size stayed
    // zero, and it could not fail. Remove the non-finite clause and the
    // NaN-stamped entry is written and then immediately swept by
    // evictTurnCache(cache, NaN), because no age compares true against NaN, so
    // the size is zero either way and the guard was pinned by nothing.
    //
    // ONE other live entry is the smallest case that tells the two versions
    // apart, and it is the case that matters: a single non-finite clock reading
    // would otherwise wipe every entry in the process on its way past.
    const cache = createTurnCache();
    writeTurnCache(cache, "live", result("live"), 1_000);
    expect(cache.size, "setup: there is something to lose").toBe(1);

    writeTurnCache(cache, "nan", result("x"), Number.NaN);
    expect(cache.has("live"), "a non-finite clock must not wipe the cache").toBe(true);
    expect(cache.has("nan"), "and must not write either").toBe(false);

    writeTurnCache(cache, null, result("x"), 1_000);
    expect(cache.size, "a null key must not add an entry nothing can ever read").toBe(1);
    expect(readTurnCache(cache, "live", 1_000)?.text, "and the survivor is intact").toBe("live");
  });

  it("the sweep uses the SAME two-sided freshness test the read does", () => {
    // Date.now() is not monotonic. One NTP step backwards is enough to leave an
    // entry stamped in the future, and the read refuses that entry on sight. A
    // sweep that only looks for entries that are too OLD keeps it forever: it
    // holds a slot against the bound that nothing can ever be served from.
    const cache = createTurnCache();
    cache.set("future", { storedAt: 20_000, text: "f", values: {}, data: {} });
    expect(
      readTurnCache(cache, "future", 10_000),
      "setup: the READ already refuses a future stamp",
    ).toBeNull();

    cache.set("future", { storedAt: 20_000, text: "f", values: {}, data: {} });
    writeTurnCache(cache, "now", result("n"), 10_000);
    expect(cache.has("future"), "what the read refuses, the sweep must drop").toBe(false);
    expect(cache.has("now")).toBe(true);
  });
});
