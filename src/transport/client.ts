// The only place in this package that touches the network.
//
// It returns the RAW parsed body and shapes nothing. That is finding M-5's
// instruction taken literally: if Transport shaped the response before Core saw
// it, Core's guard could never fire, and the architecture that separates them
// would be providing false comfort rather than a boundary.
//
// Every bound H-2 asks for is enforced here, at the edge, before a byte is
// parsed: a request timeout, a response size cap, and an outbound URL that has
// been through the allowlist.

import { BOUNDS } from "../core/bounds.ts";
import { assertAllowedNodeUrl } from "../core/node-url.ts";
import { ok, type Result, refuse } from "../core/result.ts";

/** The shape of fetch this package needs. Injected so tests never hit the network. */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: string;
    signal: AbortSignal;
  },
) => Promise<unknown>;

interface ResponseLike {
  status: number;
  text: () => Promise<string>;
  body?: {
    getReader?: () => {
      read: () => Promise<{ done: boolean; value?: Uint8Array }>;
      cancel: () => Promise<unknown>;
    };
  } | null;
}

function isResponseLike(v: unknown): v is ResponseLike {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as ResponseLike).status === "number" &&
    typeof (v as ResponseLike).text === "function"
  );
}

/**
 * Read a body while counting bytes, and abort as soon as the cap is passed.
 *
 * Reading the whole body and then measuring it would report the right error
 * after already paying the whole cost, which is not a cap.
 */
async function readCapped(res: ResponseLike, maxBytes: number): Promise<Result<string>> {
  const reader = res.body?.getReader?.();

  if (!reader) {
    const text = await res.text();
    if (typeof text !== "string") {
      return refuse("RESPONSE_MALFORMED", "The XRPL node response body could not be read.");
    }
    if (text.length > maxBytes) {
      return refuse(
        "RESPONSE_TOO_LARGE",
        "The XRPL node response was larger than this plugin will read, so it was refused.",
      );
    }
    return ok(text);
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return refuse(
        "RESPONSE_TOO_LARGE",
        "The XRPL node response was larger than this plugin will read, so it was refused.",
      );
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return ok(new TextDecoder().decode(merged));
}

export interface RpcOptions {
  readonly fetchImpl: FetchLike;
  readonly nodeUrl: string;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
}

/**
 * One XRPL JSON-RPC call. Returns the raw parsed body, untouched.
 *
 * MEASURED 2026-08-31: rippled answers errors with HTTP 200 and the failure in
 * the body, so a healthy status here proves nothing about the content. Deciding
 * what the body means is core/response.ts's job, not this function's.
 */
export async function rpcCall(
  method: string,
  params: Record<string, unknown>,
  options: RpcOptions,
): Promise<Result<unknown>> {
  const allowed = assertAllowedNodeUrl(options.nodeUrl);
  if (!allowed.ok) return allowed;

  const timeoutMs = options.timeoutMs ?? BOUNDS.REQUEST_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? BOUNDS.MAX_RESPONSE_BYTES;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await options.fetchImpl(allowed.value, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ method, params: [params] }),
      signal: controller.signal,
    });

    if (!isResponseLike(res)) {
      return refuse(
        "NODE_UNREACHABLE",
        "The XRPL node returned something that was not an HTTP response, so the lookup was refused.",
      );
    }

    if (res.status !== 200) {
      return refuse(
        "NODE_UNREACHABLE",
        `The XRPL node answered with HTTP ${res.status}, so no ledger data was retrieved.`,
      );
    }

    const body = await readCapped(res, maxBytes);
    if (!body.ok) return body;

    try {
      return ok(JSON.parse(body.value));
    } catch {
      return refuse(
        "RESPONSE_MALFORMED",
        "The XRPL node response was not valid JSON, so the lookup was refused.",
      );
    }
  } catch {
    // AbortError and every network failure land here. Neither is allowed to
    // escape as an exception: on this runtime a thrown error becomes silence.
    const aborted = controller.signal.aborted;
    return refuse(
      aborted ? "NODE_TIMEOUT" : "NODE_UNREACHABLE",
      aborted
        ? `The XRPL node did not answer within ${timeoutMs}ms, so the lookup was abandoned and no data was retrieved.`
        : "The XRPL node could not be reached, so no ledger data was retrieved.",
    );
  } finally {
    clearTimeout(timer);
  }
}
