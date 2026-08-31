// Finding M-4. The security pass asked where the node URL comes from and noted
// that the answer decides whether this is SSRF. The architecture role resolved
// it: pin it as a constant.
//
// So v1 has no way to configure it. There is no environment variable, no
// character-config key, and nothing reads it from conversation. The plugin
// declares zero pluginParameters.
//
// The guard below therefore has no hostile caller today, and it exists anyway,
// and it runs against the pinned constant itself at module load. The constant is
// a string in a file, and the next person to edit it is the threat model.
//
// REWRITTEN after an adversarial red-proof confirmed six mutations the test
// suite could not see. Two were defects in this file rather than in its tests:
//
//   1. An earlier version of this comment claimed that "blocking private and
//      loopback ranges by literal is belt-and-braces here". NO SUCH CODE
//      EXISTED. The refusal of 169.254.169.254 came entirely from the allowlist,
//      so appending any IP literal to ALLOWED_NODE_HOSTS silently made it a
//      permitted egress target. A security file that describes a control it does
//      not implement is worse than one that says nothing, because it answers the
//      audit on that control's behalf. The checks below are real, and they run
//      BEFORE the allowlist so they hold however the allowlist is later edited.
//
//   2. The function returned the parsed URL stringified, which carries userinfo
//      through verbatim. The credential check itself was correct, but the
//      returned value was only ever as safe as that one check. The outbound URL
//      is now REBUILT from individually validated components, so a credential
//      cannot survive even if the credential branch is later weakened. Kickoff
//      step 6: structure so the secure path is the default path.

import { ok, type Result, refuse } from "./result.ts";

/**
 * Hosts this plugin will talk to. Exact hostname matches only.
 *
 * Not a suffix test: that also accepts evil-xrplcluster.com and
 * xrplcluster.com.attacker.test. Not a subdomain wildcard either: a subdomain
 * the operator does not control (dangling DNS, a takeover, a co-tenanted CDN
 * name) is not the same trust boundary as the apex.
 */
export const ALLOWED_NODE_HOSTS: readonly string[] = [
  "xrplcluster.com",
  "s1.ripple.com",
  "s2.ripple.com",
];

/**
 * Ports this plugin will talk to. Empty means the scheme default.
 *
 * 51234 is rippled's public JSON-RPC port. Restricting the set matters because
 * an unrestricted port turns any future allowlist mistake into an internal port
 * scanner.
 */
export const ALLOWED_NODE_PORTS: readonly string[] = ["", "443", "51234"];

/**
 * The node this plugin reads from. Public, read-only, no credentials.
 *
 * VERIFIED 2026-08-31: answered server_info with rippled 3.3.0 and
 * complete_ledgers 32570-106661700, so it carries full history.
 *
 * Perishable. A public endpoint can be withdrawn or change operator without
 * notice. Re-check before relying on it.
 */
export const XRPL_NODE_URL = "https://xrplcluster.com/";

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Hostnames that are never a public XRPL node, whatever an allowlist says. */
const FORBIDDEN_NAMES = new Set(["localhost", "localhost.localdomain", "ip6-localhost"]);
const FORBIDDEN_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain", ".home.arpa"];

/**
 * True for a host this plugin must never talk to, whatever the allowlist says.
 *
 * EXPORTED, and that is the point rather than convenience. Two earlier versions
 * of this logic sat inline inside assertAllowedNodeUrl BELOW the allowlist
 * check, so no input could ever reach them: an IP literal is not on a list of
 * domain names, so the allowlist refused it first and the literal checks were
 * unreachable. The mutation harness proved it twice, by disabling each in turn
 * and watching the suite stay green.
 *
 * Unreachable defence in depth is not defence in depth, it is reassurance. A
 * layer that cannot be reached also cannot be tested, and a layer that cannot
 * be tested is the one that quietly stops working.
 *
 * So it is a named predicate with its own direct tests, and it runs BEFORE the
 * allowlist. It holds even if someone later puts an IP on the allowlist, which
 * is precisely the edit an adversarial pass used to get in.
 */
export function isNeverAValidNodeHost(host: unknown): boolean {
  if (typeof host !== "string") return true;
  const h = host
    .toLowerCase()
    .trim()
    .replace(/\.$/, "")
    .replace(/^\[|\]$/g, "");

  if (h === "") return true;
  if (FORBIDDEN_NAMES.has(h)) return true;
  if (FORBIDDEN_SUFFIXES.some((suffix) => h.endsWith(suffix))) return true;
  // An IPv6 literal is the only host form containing a colon once the port has
  // been split off by the URL parser.
  if (h.includes(":")) return true;
  // EVERY bare IPv4 address, not just the private ranges. Strictly stronger
  // than a range blocklist and one branch instead of eight, so there is nothing
  // to get subtly wrong.
  if (IPV4.test(h)) return true;
  // Integer and hex forms of an IP address: http://2130706433/ is 127.0.0.1.
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/.test(h)) return true;
  return false;
}

/**
 * Reject anything that is not an exact, credential-free, https URL on the
 * allowlist, then rebuild the outbound URL from the parts that were validated.
 */
export function assertAllowedNodeUrl(input: unknown): Result<string> {
  if (typeof input !== "string" || input.trim() === "") {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      "The XRPL node URL was not a non-empty string, so it was refused.",
    );
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      "The XRPL node URL could not be parsed, so it was refused.",
    );
  }

  if (url.protocol !== "https:") {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      `The XRPL node URL used ${url.protocol} rather than https, so it was refused.`,
    );
  }

  // https://xrplcluster.com@attacker.test/ has hostname attacker.test. Refusing
  // any userinfo removes the whole class rather than reasoning about it.
  if (url.username !== "" || url.password !== "") {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      "The XRPL node URL carried credentials in its userinfo, so it was refused. A credential in a URL is transmitted to the network.",
    );
  }

  const host = url.hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[|\]$/g, "");

  // Runs BEFORE the allowlist, so it holds however the allowlist is edited.
  //
  // LIMIT, stated rather than implied: this inspects the hostname, not the
  // address DNS resolves it to. It does not defend against an allowlisted name
  // resolving to a private address. That needs resolve-then-check plus a
  // re-check after every redirect, which is a larger change than v1 needs while
  // the allowlist holds three fixed public hosts.
  if (isNeverAValidNodeHost(host)) {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      "The XRPL node URL named a host this plugin will never talk to (a local name, an IP literal, or an unparseable host), so it was refused.",
    );
  }

  if (!ALLOWED_NODE_HOSTS.includes(host)) {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      "The XRPL node URL was not on the allowlist, so it was refused.",
    );
  }

  if (!ALLOWED_NODE_PORTS.includes(url.port)) {
    return refuse(
      "NODE_URL_NOT_ALLOWED",
      `The XRPL node URL used port ${url.port}, which is not on the allowlist, so it was refused.`,
    );
  }

  // Rebuilt, not passed through. Only components checked above appear in the
  // string that reaches fetch, so userinfo, a fragment, or anything else in the
  // original cannot ride along.
  const port = url.port === "" ? "" : `:${url.port}`;
  return ok(`https://${host}${port}${url.pathname}${url.search}`);
}

// The pinned constant is checked against its own guard when this module loads.
// If an edit ever puts something unreachable or unsafe in XRPL_NODE_URL, this
// fails at import rather than at the first lookup.
const pinnedCheck = assertAllowedNodeUrl(XRPL_NODE_URL);
if (!pinnedCheck.ok) {
  throw new Error(`XRPL_NODE_URL is not on its own allowlist: ${pinnedCheck.message}`);
}
