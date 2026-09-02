// One lookup per turn, decided here rather than inside the provider's closure.
//
// Why a cache exists at all: the provider declares alwaysInResponseState, which
// puts it in the stage-1 router prompt as well as the stage-2 planner's, so the
// runtime can ask it more than once per turn.
//
// PROVENANCE OF THE NUMBER, because it is stated as measured and this repo does
// not produce it. 718ms then 571ms, two full network reads of identical data in
// one turn, was measured OUTSIDE this repo on a running elizaOS agent with this
// provider registered. It is REPORTED here, not reproduced: driving the pinned
// core's real message path from src/__tests__/ yields ONE provider ask per turn
// every time, and no test in this tree constructs a two-ask turn.
//
// What this repo does verify: the doubled ask is architecturally reachable,
// because composeState runs every selected provider on each call and stage 1 and
// the planner are two separate composes; and the real runtime hands this
// provider the inbound message.id and a UUID agentId, so the key shape is right
// end to end. The cost half is the smaller half in any case. The larger half is
// that the router and the planner would otherwise be able to observe two
// different balances inside one turn and answer from either.
//
// Why the decisions live HERE and only the Map lives in the closure: exactly the
// reason checkRateLimit and pruneWindow are exported and pure. src/core/
// response.ts and src/core/node-url.ts each record a validator that sat inside a
// closure where no test could reach it, and an unreachable guard is the one that
// quietly stops working.
//
// No single-flight, and that is deliberate rather than an omission. Stage 1 is
// awaited before the planner runs, so the two calls of a turn are sequential and
// a plain value cache hits; concurrent turns carry different message ids and so
// land on different keys. There is no defect behind a promise-sharing layer here
// and adding one would be a layer no test could make fail.

import { BOUNDS } from "./bounds.ts";

/**
 * The byte between key components.
 *
 * Written as an escape because CLAUDE.md bans literal control characters in
 * source and checks/failopen_lint.ts fails the build on them. NUL cannot appear
 * in a UUID, in Ripple base58, or in a decimal integer, so no component can
 * forge a boundary and no two distinct inputs can concatenate to one key.
 */
export const TURN_CACHE_KEY_SEPARATOR = "\u0000";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Everything this package puts in a ProviderResult's values or data. */
export type CachedScalar = string | number | boolean;

/** The three fields of a ProviderResult, all present. */
export interface CachedResult {
  readonly text: string;
  readonly values: Readonly<Record<string, CachedScalar>>;
  readonly data: Readonly<Record<string, CachedScalar>>;
}

export interface TurnCacheEntry extends CachedResult {
  readonly storedAt: number;
}

export type TurnCache = Map<string, TurnCacheEntry>;

/** What a key is built from. Every field is `unknown` because every field is input. */
export interface TurnCacheKeyInput {
  /**
   * From the RUNTIME, never from message.agentId. That field is declared
   * optional and is caller-shaped, so keying on it would let whoever wrote the
   * message choose which partition to read.
   */
  readonly agentId: unknown;
  readonly messageId: unknown;
  /** The VALIDATED address, never the raw candidate the pattern found. */
  readonly address: unknown;
  readonly skipped: unknown;
  readonly now: unknown;
}

export function createTurnCache(): TurnCache {
  return new Map();
}

/**
 * True for a string in canonical UUID shape.
 *
 * Memory.id is declared `id?: UUID` and UUID is an unbranded string, so absence
 * and arbitrary strings are both real inputs. A template literal would coerce a
 * missing id to "undefined" and hand every id-less message in the process one
 * shared partition.
 */
export function isUuidLike(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

/**
 * Build the key for one turn, or null when the turn cannot be cached safely.
 *
 * Null is the safe direction. A turn with no key does the real work twice, which
 * is the behaviour this module removes, not a behaviour it breaks.
 */
export function turnCacheKey(input: TurnCacheKeyInput): string | null {
  if (!isUuidLike(input.agentId)) return null;
  if (!isUuidLike(input.messageId)) return null;
  if (typeof input.address !== "string" || input.address === "") return null;

  const skipped = input.skipped;
  if (typeof skipped !== "number" || !Number.isInteger(skipped) || skipped < 0) return null;

  // A corrupt clock is refused HERE rather than downstream. checkRateLimit fails
  // CLOSED on a non-finite clock, and a key built on one would put a cache read
  // in front of a limiter that would have refused the lookup.
  if (!Number.isFinite(input.now)) return null;

  return [input.agentId, input.messageId, input.address, String(skipped)].join(
    TURN_CACHE_KEY_SEPARATOR,
  );
}

/**
 * Two-sided on purpose, and it OWNS non-finite.
 *
 * `age <= TTL` alone is true for every negative age, which makes an entry
 * written under a clock that later ran backwards permanently fresh. Date.now()
 * is not monotonic and an NTP step is enough, so that clock is reachable in
 * production and not only through the test seam.
 *
 * Non-finite is this function's job and no caller repeats it. A NaN storedAt or
 * now gives a NaN age, which fails `age >= 0`; +Infinity gives -Infinity, which
 * fails the same test; -Infinity gives +Infinity, which fails `age <= TTL`. All
 * three are refused here with the identical outcome, so a second check upstream
 * could not change a result and would be a guard no mutation could kill.
 *
 * What it does NOT own is the TYPE. `now - "1000"` coerces, so a string stamp
 * would read as a real age. readTurnCache rejects that before calling this.
 */
function isFresh(storedAt: number, now: number): boolean {
  const age = now - storedAt;
  return age >= 0 && age <= BOUNDS.TURN_CACHE_TTL_MS;
}

/**
 * Drop what has expired, then what does not fit.
 *
 * Called on INSERT, which is the only path that grows the map. On read it would
 * leave a burst of writes with no reads between them unbounded, and a burst of
 * writes with no reads is what a flood of turns looks like. A lookup is never
 * refused because the cache is full: for a cache, the safe direction on every
 * unknown is to fall through and do the real work.
 */
function evictTurnCache(cache: TurnCache, now: number): void {
  for (const [key, entry] of cache) {
    if (!isFresh(entry.storedAt, now)) cache.delete(key);
  }

  // Map iterates in insertion order, so the first key is the oldest.
  while (cache.size > BOUNDS.TURN_CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) return;
    cache.delete(oldest);
  }
}

export function writeTurnCache(
  cache: TurnCache,
  key: string | null,
  result: CachedResult,
  now: number,
): void {
  if (key === null || !Number.isFinite(now)) return;
  // Copied in, not referenced in. The caller hands back the same object it
  // returns to the runtime, and a consumer that mutates it must not be able to
  // rewrite what a later hit serves.
  cache.set(key, {
    storedAt: now,
    text: result.text,
    values: { ...result.values },
    data: { ...result.data },
  });
  evictTurnCache(cache, now);
}

/**
 * Serve one turn's stored result, or null.
 *
 * Every unknown is a miss AND a delete. A cache is the one place where falling
 * through to the real work is always safe, so nothing here has to guess what a
 * malformed entry was supposed to mean.
 */
export function readTurnCache(
  cache: TurnCache,
  key: string | null,
  now: number,
): CachedResult | null {
  if (key === null) return null;

  const entry: unknown = cache.get(key);
  if (entry === undefined) return null;
  if (typeof entry !== "object" || entry === null) {
    cache.delete(key);
    return null;
  }

  const held = entry as Partial<TurnCacheEntry>;
  if (typeof held.text !== "string") {
    cache.delete(key);
    return null;
  }
  // TYPE only. Non-finite is isFresh's job and it refuses all three cases with
  // the identical outcome, so repeating it here would be a clause that cannot
  // change a result. The type check cannot be dropped the same way: `now - "1000"`
  // coerces, so a string stamp would otherwise reach isFresh and read as fresh.
  if (typeof held.storedAt !== "number") {
    cache.delete(key);
    return null;
  }
  if (typeof held.values !== "object" || held.values === null) {
    cache.delete(key);
    return null;
  }
  if (typeof held.data !== "object" || held.data === null) {
    cache.delete(key);
    return null;
  }
  if (!isFresh(held.storedAt, now)) {
    cache.delete(key);
    return null;
  }

  // A FRESH object every time. Handing back the stored one lets a consumer that
  // mutates its result poison every later hit on that key.
  return { text: held.text, values: { ...held.values }, data: { ...held.data } };
}
