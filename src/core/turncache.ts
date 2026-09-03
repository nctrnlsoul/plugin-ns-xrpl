// One lookup per turn, decided here rather than inside the provider's closure.
//
// Why a cache exists at all: the provider declares alwaysInResponseState, which
// puts it in the stage-1 response state as well as the stage-2 planner's, so the
// runtime can ask it more than once per turn. CAN, not will. Whether the runtime
// goes on to run the planner stage depends on what stage 1 produces, so the
// second ask is what this absorbs when it happens, not something it assumes.
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

import { createHash } from "node:crypto";
import { BOUNDS } from "./bounds.ts";

/**
 * The byte between key components.
 *
 * Written as an escape because CLAUDE.md bans literal control characters in
 * source and checks/failopen_lint.ts fails the build on them. NUL cannot appear
 * in a UUID, in Ripple base58, or in lowercase hex, so no component can forge a
 * boundary and no two distinct inputs can concatenate to one key.
 */
export const TURN_CACHE_KEY_SEPARATOR = "\u0000";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The exact shape skippedDigest produces, and the only shape the key admits.
 *
 * ANCHORED and without /g. A /g pattern makes `.test()` stateful, so every
 * second call on the same string returns false; src/core/render.ts records that
 * measurement against a candidate pattern that carries the flag.
 */
const SKIPPED_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

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
  /**
   * The DIGEST of the skipped-address list, the unreadable-run count AND the
   * capped flag, from skippedDigest below. One value for all three, so they
   * cannot disagree.
   *
   * A digest and not a count, because the report this key serves is determined
   * by the skipped IDENTITIES and not only by how many there were. Under the
   * count form, one agentId and one message.id with turn 1 saying "A and B" and
   * turn 2 saying "A and C" produced ONE key: turn 2 hit, and was served a
   * report naming B, an address its message never held, while C vanished with no
   * notice and every count in the report still added up. Memory.id is
   * caller-shaped, which is why isUuidLike exists, so that collision is
   * reachable rather than hypothetical.
   *
   * One value, so the identities and the count cannot disagree.
   */
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
 * One value standing for everything about the MESSAGE that shapes the report,
 * or null.
 *
 * The key has to be determined by what the REPORT is determined by. The report
 * names the skipped addresses, so a component carrying only how many there were
 * lets two different messages share one entry, and the served report then
 * describes a message that was never sent.
 *
 * THREE FACTS, ONE COMPONENT. The report is determined by the skipped
 * identities, AND by how many runs of address-shaped characters the message
 * held that could not be read, AND by whether the checksum budget stopped the
 * scan before it had examined them all. Each of the last two is printed as its
 * own notice, so each of them determines the report.
 *
 * F8 REPRODUCED the collision on the count: same agentId, same message.id, same
 * subject, same skipped list, one poisoned run in turn 1 and two in turn 2.
 * Turn 2 was served turn 1's report, which states one, and the second run
 * vanished with every count in the served report still adding up.
 *
 * The capped flag was the SAME defect one field over, and it is the worse half:
 * `capped` says the report is INCOMPLETE. Two turns sharing a caller-supplied
 * message.id, identical but for the cap, were one key, so one of them was
 * served an incompleteness notice for a scan that finished, or lost the notice
 * for a scan that did not. A report that silently drops "this is incomplete"
 * reads as a complete one, which is invariant 10 inverted.
 *
 * Three components would be three values that can disagree; hashing them
 * together is what makes disagreement unrepresentable.
 *
 * Null on anything that is not a list of strings, and null is the safe
 * direction: no key means the real work runs twice, which is the behaviour this
 * module removes rather than one it breaks. A non-string entry cannot be
 * rendered and cannot be compared as one, so digesting it would key on a
 * coercion. The same holds for the count: a fractional, negative or non-finite
 * one is a number nothing in this package can have measured. And for the flag:
 * the scan either finished or it did not, so anything that is not a boolean is
 * an answer no scan produced.
 *
 * Order and length are both carried, because the report prints the names in
 * order and counts them.
 *
 * The separator is what stops ["ab","c"] and ["a","bc"] digesting to one value.
 * KNOWN LIMIT, stated rather than implied: an entry that itself contained NUL
 * could forge a boundary, and an EMPTY list digests identically to a list
 * holding one empty string. Nothing in this package produces either, because
 * these come from a base58 candidate pattern, and a caller that supplies one
 * gets a shared cache entry rather than anything it could not already have
 * supplied.
 */
export function skippedDigest(
  candidates: unknown,
  unreadable: unknown,
  capped: unknown,
): string | null {
  if (!Array.isArray(candidates)) return null;
  for (const c of candidates) {
    if (typeof c !== "string") return null;
  }
  if (typeof unreadable !== "number" || !Number.isSafeInteger(unreadable) || unreadable < 0) {
    return null;
  }
  // A BOOLEAN or nothing, the same discipline the count gets. `!!capped` and
  // `capped ?? false` both always produce a component, and a component that
  // always exists is one that can never say "do not cache this turn". Rule 7,
  // and checks/failopen_lint.ts fails the build on that shape.
  if (typeof capped !== "boolean") return null;

  // The two scalars in a FIXED position ahead of the list, each followed by the
  // separator, which is what stops either of them being confused with a member
  // of the list or with each other. Built in two statements only so no line runs
  // past the formatter's width; the string is exactly the concatenation it
  // reads as.
  const scalars = `${String(unreadable)}${TURN_CACHE_KEY_SEPARATOR}${String(capped)}`;
  return createHash("sha256")
    .update(
      `${scalars}${TURN_CACHE_KEY_SEPARATOR}${candidates.join(TURN_CACHE_KEY_SEPARATOR)}`,
      "utf8",
    )
    .digest("hex");
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

  // The EXACT digest shape, and nothing else. A count, a raw list and an absent
  // value are all refused here rather than stringified into a component, because
  // String(anything) always produces a component and a component that always
  // exists is a component that can never say "do not cache this turn".
  const skipped = input.skipped;
  if (typeof skipped !== "string" || !SKIPPED_DIGEST_PATTERN.test(skipped)) return null;

  // A corrupt clock is refused HERE rather than downstream. checkRateLimit fails
  // CLOSED on a non-finite clock, and a key built on one would put a cache read
  // in front of a limiter that would have refused the lookup.
  if (!Number.isFinite(input.now)) return null;

  return [input.agentId, input.messageId, input.address, skipped].join(TURN_CACHE_KEY_SEPARATOR);
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
