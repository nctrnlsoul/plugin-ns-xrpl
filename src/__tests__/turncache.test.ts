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
  skippedDigest,
  TURN_CACHE_KEY_SEPARATOR,
  turnCacheKey,
  writeTurnCache,
} from "../core/turncache.ts";

const AGENT = "11111111-2222-4333-8444-555555555555";
const MESSAGE = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const PEER = "rKUK9omZqVEnraCipKNFb5q4tuNTeqEDZS";
const THIRD = "rNjV3CeZ8puSpeiZqDmjAvfwxufLsiYRRX";

/** The digest a turn that skipped nothing and read every run carries. */
const NO_SKIPPED = String(skippedDigest([], 0));

const GOOD = { agentId: AGENT, messageId: MESSAGE, address: ADDR, skipped: NO_SKIPPED, now: 1_000 };

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

// The key used to carry the skipped COUNT, and the report it serves stopped
// being determined by a count the moment the notice started NAMING addresses.
//
// REPRODUCED against the count form: one agentId, one message.id, turn 1 saying
// "A and B" and turn 2 saying "A and C", two distinct valid addresses and a
// skipped count of 1 either side, inside the TTL. Turn 2 reported cacheState
// "hit" and served turn 1's report, which names B. B was never in turn 2's
// message and C vanished with no notice, while every count in the report still
// added up. Memory.id is caller-shaped input, which is why isUuidLike exists, so
// that collision is reachable rather than hypothetical.
//
// The key component is therefore a DIGEST of the list. Identities and count are
// one value and cannot disagree.
describe("the skipped digest is determined by what the report is determined by", () => {
  it("digests a list of strings to a fixed lowercase hex shape", () => {
    const d = skippedDigest([PEER], 0);
    expect(d, "a list of strings must produce a digest").not.toBeNull();
    expect(d).toMatch(/^[0-9a-f]{64}$/);
    expect(NO_SKIPPED, "and so must the empty list").toMatch(/^[0-9a-f]{64}$/);
  });

  it("is stable: the same list twice is the same digest", () => {
    expect(skippedDigest([PEER, THIRD], 0)).toBe(skippedDigest([PEER, THIRD], 0));
  });

  it("THRESHOLD: two lists of the SAME LENGTH with DIFFERENT MEMBERS differ", () => {
    // The property the count form did not have, and the only one that matters:
    // one member changed, the length unchanged. A count agrees on both of these
    // and the report does not.
    expect(skippedDigest([PEER], 0)).not.toBe(skippedDigest([THIRD], 0));
    expect(skippedDigest([ADDR, PEER], 0)).not.toBe(skippedDigest([ADDR, THIRD], 0));
  });

  it("carries the ORDER, because the report names them in order", () => {
    expect(skippedDigest([PEER, THIRD], 0)).not.toBe(skippedDigest([THIRD, PEER], 0));
  });

  it("carries the LENGTH too, so a shorter list is a different digest", () => {
    expect(skippedDigest([PEER], 0)).not.toBe(skippedDigest([PEER, THIRD], 0));
  });

  it("cannot be forged by concatenation: no two distinct lists share a digest", () => {
    // Without a separator, ["ab","c"] and ["a","bc"] concatenate to one string
    // and one digest, so two different messages would read each other's report.
    expect(skippedDigest(["ab", "c"], 0)).not.toBe(skippedDigest(["a", "bc"], 0));
    expect(skippedDigest(["a", "", "b"], 0)).not.toBe(skippedDigest(["a", "b"], 0));
  });

  it("REFUSES anything that is not a list, so nothing is claimed about it", () => {
    for (const bad of [undefined, null, 0, 1, "1", {}, true, new Set([PEER])]) {
      expect(skippedDigest(bad, 0), JSON.stringify(bad)).toBeNull();
    }
  });

  it("REFUSES a list holding anything that is not a string", () => {
    // A non-string entry cannot be rendered and cannot be compared as one, so
    // digesting it would key on a coercion. Null is the safe direction: no key
    // means the real work runs twice, which is the behaviour the cache removes.
    for (const bad of [
      [1],
      [PEER, 2],
      [null],
      [undefined],
      [{}],
      [[PEER]],
      [PEER, Symbol.iterator],
    ]) {
      expect(skippedDigest(bad, 0), JSON.stringify(bad.map(String))).toBeNull();
    }
  });

  // F8, one layer out from F7 and the SAME defect. The report is determined by
  // the skipped identities AND by how many runs the message held that this
  // plugin could not read, because both are printed. A digest carrying only the
  // identities makes two turns that differ by the unreadable count share one
  // entry, and the second is served a report stating a number its own message
  // never produced, with every count in it still adding up.
  //
  // MEASURED against the identities-only form: same agentId, same message.id,
  // same subject, same skipped list, one poisoned run in turn 1 and two in turn
  // 2. Turn 2 reported "hit" and was served turn 1's report, so the second run
  // vanished exactly as it did before this change existed.
  it("THRESHOLD: the same list with DIFFERENT unreadable counts is a different digest", () => {
    // One, not a comfortable large number. The smallest disagreement that must
    // split the key is zero runs against one.
    expect(skippedDigest([], 0)).not.toBe(skippedDigest([], 1));
    expect(skippedDigest([PEER], 1)).not.toBe(skippedDigest([PEER], 2));
    expect(skippedDigest([PEER, THIRD], 0)).not.toBe(skippedDigest([PEER, THIRD], 1));
  });

  it("is ONE component, so the identities and the count cannot disagree", () => {
    // The rule F7 earned, applied to the second thing the report is determined
    // by: A KEY MUST BE DETERMINED BY WHAT THE THING IT KEYS IS DETERMINED BY.
    // Two components would be two values that can drift apart, which is the
    // shape this repo keeps finding.
    const seen = new Set<string | null>();
    for (const list of [[], [PEER], [THIRD], [PEER, THIRD]]) {
      for (const runs of [0, 1, 2]) {
        seen.add(skippedDigest(list, runs));
      }
    }
    expect(seen.size, "every (list, count) pair is its own digest").toBe(12);
  });

  it("the count cannot be confused with a member of the list", () => {
    // The separator's job, extended to the new component. Without it a count of
    // 1 beside no addresses and no count beside the address "1" would collide.
    expect(skippedDigest(["1"], 0)).not.toBe(skippedDigest([], 1));
    expect(skippedDigest([], 10)).not.toBe(skippedDigest(["0"], 1));
  });

  it("is stable: the same list and the same count twice is the same digest", () => {
    expect(skippedDigest([PEER], 3)).toBe(skippedDigest([PEER], 3));
  });

  it("REFUSES a count that is not a non-negative safe integer, so nothing is keyed on it", () => {
    // Null is the safe direction here for the same reason it is above: no key
    // means the real work runs twice, which is the behaviour this module
    // removes rather than one it breaks. A negative or fractional count is a
    // number nothing in this package can have measured.
    for (const bad of [
      undefined,
      null,
      -1,
      -0.5,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      Number.MAX_SAFE_INTEGER + 1,
      "1",
      "",
      {},
      [],
      true,
    ]) {
      expect(skippedDigest([PEER], bad), JSON.stringify(bad)).toBeNull();
    }
    // Rule 95: prove the setup. The same list WITH a usable count digests, so
    // the nulls above came from the component under test.
    expect(skippedDigest([PEER], 0)).not.toBeNull();
    expect(skippedDigest([PEER], Number.MAX_SAFE_INTEGER)).not.toBeNull();
  });
});

describe("the key admits only what it can safely partition on", () => {
  it("builds a key from a complete, well-formed input", () => {
    expect(turnCacheKey(GOOD)).toBe(
      [AGENT, MESSAGE, ADDR, NO_SKIPPED].join(TURN_CACHE_KEY_SEPARATOR),
    );
  });

  it("separates components with a byte none of them can contain", () => {
    // Not decoration. Without a separator no component can forge, two different
    // (agent, message) pairs can concatenate to one string. NUL cannot appear in
    // a UUID, in Ripple base58, or in lowercase hex.
    expect(TURN_CACHE_KEY_SEPARATOR).toBe(String.fromCharCode(0));
    expect(AGENT.includes(TURN_CACHE_KEY_SEPARATOR)).toBe(false);
    expect(ADDR.includes(TURN_CACHE_KEY_SEPARATOR)).toBe(false);
    expect(NO_SKIPPED.includes(TURN_CACHE_KEY_SEPARATOR)).toBe(false);
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

  it("REFUSES a skipped component that is not the exact digest shape", () => {
    // The digest is the only shape this key will partition on. A count, a raw
    // list, an absent value and a near-miss hex string are all refused, and each
    // is refused by the SHAPE test rather than by some other branch: the rest of
    // GOOD is well formed, so nothing else here can return null.
    for (const bad of [
      0,
      1,
      "0",
      "1",
      undefined,
      null,
      [],
      [PEER],
      "",
      NO_SKIPPED.slice(0, -1),
      `${NO_SKIPPED}0`,
      NO_SKIPPED.toUpperCase(),
      `${NO_SKIPPED.slice(0, -1)}g`,
    ]) {
      expect(turnCacheKey({ ...GOOD, skipped: bad }), JSON.stringify(bad)).toBeNull();
    }
    // Rule 95: prove the setup. The same input WITH the digest builds a key, so
    // the nulls above came from the component under test.
    expect(turnCacheKey(GOOD)).not.toBeNull();
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

  it("THRESHOLD: two skipped lists of the SAME LENGTH with DIFFERENT MEMBERS are different keys", () => {
    // The property the count form did not have. Under it, "A and B" and "A and
    // C" in one turn were one key, so the second turn was served a report NAMING
    // B, an address its message never held, while C vanished with no notice and
    // every count still added up.
    const withB = turnCacheKey({ ...GOOD, skipped: String(skippedDigest([PEER], 0)) });
    const withC = turnCacheKey({ ...GOOD, skipped: String(skippedDigest([THIRD], 0)) });
    expect(withB, "setup: both must actually build a key").not.toBeNull();
    expect(withC).not.toBeNull();
    expect(withB).not.toBe(withC);
  });

  it("carries the skipped list at a threshold of ONE, so the notice cannot be lost", () => {
    // The report text differs by exactly the other-address lines when this
    // differs, and rule 10 says that omission is always spoken. A key that drops
    // it serves a report missing the notice.
    expect(turnCacheKey({ ...GOOD, skipped: String(skippedDigest([PEER], 0)) })).not.toBe(
      turnCacheKey(GOOD),
    );
  });

  it("carries the unreadable-run count at a threshold of ONE, so that notice cannot be lost", () => {
    // The same property one field over. The two reports differ by exactly the
    // unreadable_address_runs line, and invariant 10 says that omission is
    // always spoken, so a key that cannot tell them apart serves a report
    // missing it.
    expect(turnCacheKey({ ...GOOD, skipped: String(skippedDigest([], 1)) })).not.toBe(
      turnCacheKey(GOOD),
    );
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
