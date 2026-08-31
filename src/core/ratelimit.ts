// V-005 requires a rate limit on anything with a network surface, and H-2 is
// why it bites here: the caller supplies the address, the read is free on chain,
// and the cost lands on whoever holds the model key.
//
// Pure function over a timestamp list. The transport owns the list, the core
// owns the decision, so the boundary case can be tested without a clock.

import { BOUNDS } from "./bounds.ts";
import { ok, type Result, refuse } from "./result.ts";

/** Timestamps are live when strictly newer than now - window. The edge is expired. */
function isLive(stamp: number, now: number): boolean {
  return stamp > now - BOUNDS.RATE_LIMIT_WINDOW_MS;
}

/**
 * Drop expired timestamps and cap what is retained.
 *
 * The cap matters: without it the history is an attacker-controlled array that
 * grows for as long as requests arrive, which is its own unbounded-consumption
 * bug sitting inside the fix for unbounded consumption.
 */
export function pruneWindow(stamps: readonly number[], now: number): number[] {
  if (!Array.isArray(stamps) || !Number.isFinite(now)) return [];
  const live = stamps.filter((s) => typeof s === "number" && Number.isFinite(s) && isLive(s, now));
  return live.slice(-BOUNDS.RATE_LIMIT_MAX_REQUESTS * 2);
}

/**
 * Decide whether one more lookup is permitted.
 *
 * Fails CLOSED on malformed state. A limiter that allows when its own history is
 * corrupt is a limiter an attacker disables by corrupting the history.
 */
export function checkRateLimit(stamps: readonly number[], now: number): Result<void> {
  if (!Array.isArray(stamps)) {
    return refuse(
      "RATE_LIMITED",
      "The rate limiter state was unreadable, so the lookup was refused.",
    );
  }
  if (typeof now !== "number" || !Number.isFinite(now)) {
    return refuse("RATE_LIMITED", "The current time was unreadable, so the lookup was refused.");
  }
  for (const s of stamps) {
    if (typeof s !== "number" || !Number.isFinite(s)) {
      return refuse(
        "RATE_LIMITED",
        "The rate limiter state contained an unreadable entry, so the lookup was refused.",
      );
    }
  }

  const live = stamps.filter((s) => isLive(s, now));
  if (live.length >= BOUNDS.RATE_LIMIT_MAX_REQUESTS) {
    const seconds = Math.ceil(BOUNDS.RATE_LIMIT_WINDOW_MS / 1000);
    return refuse(
      "RATE_LIMITED",
      `This plugin's rate limit of ${BOUNDS.RATE_LIMIT_MAX_REQUESTS} XRPL lookups per ${seconds} seconds has been reached, so the lookup was refused and no ledger data was retrieved.`,
    );
  }

  return ok(undefined);
}
