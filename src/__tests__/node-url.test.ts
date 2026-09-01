// Row 7 of the fail-closed table: "Node URL is on the allowlist -> REFUSE.
// This is M-4."
//
// v1 pins the node URL as a constant and exposes no way to configure it, so
// this guard has no hostile caller today. It exists anyway, and it runs against
// the pinned constant itself, because the constant is a string in a file that a
// future edit can change. A guard that only exists once the feature is
// configurable is a guard written after the SSRF.
//
// Written before src/core/node-url.ts exists.

import { describe, expect, it } from "vitest";
import {
  ALLOWED_NODE_HOSTS,
  assertAllowedNodeUrl,
  isNeverAValidNodeHost,
  XRPL_NODE_URL,
} from "../core/node-url.ts";

describe("assertAllowedNodeUrl", () => {
  it("accepts the pinned constant the plugin actually ships with", () => {
    const r = assertAllowedNodeUrl(XRPL_NODE_URL);
    expect(r.ok, `the shipped constant ${XRPL_NODE_URL} must pass its own guard`).toBe(true);
  });

  it("REFUSES http, so a downgrade cannot happen quietly", () => {
    const r = assertAllowedNodeUrl("http://xrplcluster.com/");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("NODE_URL_NOT_ALLOWED");
  });

  it("REFUSES the cloud metadata address", () => {
    // Security Playbook names 169.254.169.254 explicitly. SSRF was present in
    // 100 percent of AI-built apps in the 2026 Tenzai study.
    for (const bad of [
      "https://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/",
      "https://[::ffff:169.254.169.254]/",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES loopback, private and link-local hosts", () => {
    for (const bad of [
      "https://localhost/",
      "https://127.0.0.1/",
      "https://10.0.0.1/",
      "https://192.168.1.1/",
      "https://172.16.0.1/",
      "https://[::1]/",
      "https://0.0.0.0/",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES non-http schemes", () => {
    for (const bad of [
      "file:///etc/passwd",
      "ftp://xrplcluster.com/",
      "gopher://xrplcluster.com/",
      "data:text/plain,hello",
      "javascript:alert(1)",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES a host that merely ends with an allowed host", () => {
    // The classic allowlist bug: endsWith("xrplcluster.com") also matches
    // evil-xrplcluster.com and xrplcluster.com.attacker.test.
    for (const bad of [
      "https://evilxrplcluster.com/",
      "https://xrplcluster.com.attacker.test/",
      "https://attacker.test/?x=xrplcluster.com",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES credentials, and a host smuggled into userinfo", () => {
    // https://xrplcluster.com@attacker.test/ has host attacker.test.
    for (const bad of [
      "https://xrplcluster.com@attacker.test/",
      "https://user:pass@xrplcluster.com/",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES unparseable and non-string input", () => {
    for (const bad of ["", "   ", "not a url", null, undefined, 42, {}, []]) {
      expect(assertAllowedNodeUrl(bad as unknown).ok, `${String(bad)} must be refused`).toBe(false);
    }
  });

  it("the allowlist is non-empty and every entry passes its own guard", () => {
    // An empty allowlist would make every call refuse, which is safe but dead.
    // A malformed entry would make the shipped default unreachable.
    expect(ALLOWED_NODE_HOSTS.length).toBeGreaterThan(0);
    for (const host of ALLOWED_NODE_HOSTS) {
      expect(assertAllowedNodeUrl(`https://${host}/`).ok, `${host} must pass`).toBe(true);
    }
  });

  it("every refusal carries a non-empty message", () => {
    const r = assertAllowedNodeUrl("http://attacker.test/");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message.trim().length).toBeGreaterThan(0);
  });
});

// Everything below was added after an adversarial red-proof confirmed six
// mutations to node-url.ts that this file could not see. The originals asserted
// only `.ok === false` on inputs that several DIFFERENT branches would refuse,
// so a weakened branch was invisible: another branch caught the test input and
// the assertion could not tell which one fired.
//
// The lesson generalises and is the reason these are grouped: a negative test
// must fail for the REASON it names, or it is pinning nothing in particular.
describe("the credential guard, pinned by reason and not only by outcome", () => {
  // The confirmed hole: the only credential test used
  // https://user:pass@xrplcluster.com/, which sets BOTH halves of the userinfo.
  // Swapping || for && therefore left the suite fully green while
  // https://sk_live_ABCDEF@xrplcluster.com/ was ALLOWED and the credential went
  // out on the wire as an Authorization header.
  it("REFUSES a URL carrying only a username", () => {
    const r = assertAllowedNodeUrl("https://sk_live_ABCDEF123456@xrplcluster.com/");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("NODE_URL_NOT_ALLOWED");
      expect(r.message.toLowerCase()).toContain("credential");
    }
  });

  it("REFUSES a URL carrying only a password", () => {
    const r = assertAllowedNodeUrl("https://:s3cr3t@xrplcluster.com/");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message.toLowerCase()).toContain("credential");
  });

  it("REFUSES both halves together, and says it was the credentials", () => {
    const r = assertAllowedNodeUrl("https://user:pass@xrplcluster.com/");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message.toLowerCase()).toContain("credential");
  });

  it("never returns a value containing an at-sign, whatever it is handed", () => {
    // The structural half. Even if every branch above were weakened, the
    // returned URL is rebuilt from validated components, so userinfo cannot
    // reach fetch.
    for (const input of [
      "https://sk_live_ABCDEF@xrplcluster.com/",
      "https://:s3cr3t@xrplcluster.com/",
      "https://user:pass@xrplcluster.com/",
      "https://xrplcluster.com/",
    ]) {
      const r = assertAllowedNodeUrl(input);
      if (r.ok) expect(r.value, `${input} must not round-trip userinfo`).not.toContain("@");
    }
  });
});

describe("the allowlist is an EXACT host match, pinned in both directions", () => {
  it("REFUSES a subdomain of an allowed host", () => {
    // Confirmed hole: the original "merely ends with" test used
    // evilxrplcluster.com and xrplcluster.com.attacker.test, neither of which a
    // subdomain-wildcard form would accept, so the wildcard mutation survived.
    // A subdomain the operator does not control is a different trust boundary.
    for (const bad of [
      "https://attacker.xrplcluster.com/",
      "https://internal.s1.ripple.com/",
      "https://a.b.xrplcluster.com/",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES a host that is a SUFFIX of an allowed host", () => {
    // Confirmed hole: reversing the comparison to h.endsWith(host) is invisible
    // to a suite whose negative hosts are all LONGER than an allowlist entry.
    for (const bad of ["https://ripple.com/", "https://com/", "https://cluster.com/"]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES an allowed host reached on a non-allowed port", () => {
    expect(assertAllowedNodeUrl("https://xrplcluster.com:8080/").ok).toBe(false);
    expect(assertAllowedNodeUrl("https://xrplcluster.com:22/").ok).toBe(false);
  });

  it("accepts rippled's public JSON-RPC port on an allowed host", () => {
    const r = assertAllowedNodeUrl("https://s1.ripple.com:51234/");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toBe("https://s1.ripple.com:51234/");
  });
});

describe("private and loopback ranges are refused BY CODE, not by the allowlist", () => {
  // Confirmed hole, and the sharpest one: an earlier comment claimed this file
  // blocked private ranges "belt-and-braces". No such code existed. Appending an
  // IP literal to ALLOWED_NODE_HOSTS made it a permitted egress target, because
  // the only thing refusing 169.254.169.254 was its absence from the allowlist.
  //
  // These assertions do not go through the allowlist. They pass a bare IP, which
  // the checks must refuse on its own terms.
  it("REFUSES every bare IPv4 address, allowlisted or not", () => {
    for (const bad of [
      "https://169.254.169.254/",
      "https://169.254.170.2/", // AWS ECS container credentials endpoint
      "https://127.0.0.1/",
      "https://10.0.0.1/",
      "https://192.168.1.1/",
      "https://172.16.0.1/",
      "https://172.31.255.255/",
      "https://100.64.0.1/", // CGNAT
      "https://0.0.0.0/",
      "https://224.0.0.1/", // multicast
      "https://8.8.8.8/", // public, still refused: this plugin talks to names
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES IPv6 literals including the mapped metadata address", () => {
    for (const bad of [
      "https://[::1]/",
      "https://[::ffff:169.254.169.254]/",
      "https://[fe80::1]/",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });

  it("REFUSES local-ish names regardless of the allowlist", () => {
    for (const bad of [
      "https://localhost/",
      "https://node.localhost/",
      "https://xrpl.internal/",
      "https://printer.local/",
    ]) {
      expect(assertAllowedNodeUrl(bad).ok, `${bad} must be refused`).toBe(false);
    }
  });
});

describe("the value handed back is the value that was checked", () => {
  it("returns a rebuilt URL rather than the caller's string", () => {
    // Confirmed hole: the function used to return the parsed URL stringified, so
    // nothing constrained the string it handed out. Nothing in the suite asserted
    // on the returned value at all.
    const r = assertAllowedNodeUrl(XRPL_NODE_URL);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value).toBe("https://xrplcluster.com/");
      expect(r.value.startsWith("https://")).toBe(true);
    }
  });

  it("drops a fragment rather than passing it through", () => {
    const r = assertAllowedNodeUrl("https://xrplcluster.com/#fragment");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).not.toContain("#");
  });

  it("normalises host case without accepting a different host", () => {
    const r = assertAllowedNodeUrl("https://XRPLCluster.COM/");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toBe("https://xrplcluster.com/");
  });
});

describe("isNeverAValidNodeHost, tested directly because it cannot be reached indirectly", () => {
  // This predicate used to be inline, below the allowlist check, where no input
  // could reach it: an IP literal is not on a list of domain names, so the
  // allowlist refused it first. The mutation harness proved it twice by
  // disabling it and watching the whole suite stay green.
  //
  // Testing it here is what makes it a control rather than reassurance. It
  // holds even if someone later puts an IP on the allowlist, which is exactly
  // the edit an adversarial pass used to get in.

  it("is TRUE for every address form that must never be an egress target", () => {
    for (const host of [
      "169.254.169.254", // cloud metadata
      "169.254.170.2", // AWS ECS container credentials
      "127.0.0.1",
      "10.0.0.1",
      "192.168.1.1",
      "172.16.0.1",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "8.8.8.8", // public, still refused: this plugin talks to names
      "::1",
      "fe80::1",
      "::ffff:169.254.169.254",
      "2130706433", // integer form of 127.0.0.1
      "0x7f000001", // hex form of 127.0.0.1
      "localhost",
      "node.localhost",
      "printer.local",
      "svc.internal",
      "box.localdomain",
      "",
      "   ",
    ]) {
      expect(isNeverAValidNodeHost(host), `${JSON.stringify(host)} must be refused`).toBe(true);
    }
  });

  it("is FALSE for the hosts this plugin actually uses", () => {
    // The negative control. A predicate that answered true to everything would
    // satisfy every assertion above and refuse the pinned node as well.
    for (const host of [...ALLOWED_NODE_HOSTS, "example.com", "sub.example.com"]) {
      expect(isNeverAValidNodeHost(host), `${host} must be permitted`).toBe(false);
    }
  });

  it("is TRUE for non-string input rather than throwing", () => {
    for (const junk of [null, undefined, 42, {}, [], true]) {
      expect(isNeverAValidNodeHost(junk), `${String(junk)}`).toBe(true);
    }
  });

  it("is not fooled by a trailing dot or bracket wrapping", () => {
    expect(isNeverAValidNodeHost("127.0.0.1.")).toBe(true);
    expect(isNeverAValidNodeHost("[::1]")).toBe(true);
    expect(isNeverAValidNodeHost("LOCALHOST")).toBe(true);
  });
});

// Both numbers-or-values this file's refusals emit survived a source-side
// enumeration: the port it quotes and the scheme it quotes were read by
// nothing, so either could have been replaced with a word and stayed green.
//
// Unreachable through the provider, which uses the pinned constant.
// assertAllowedNodeUrl is an EXPORT and is the guard M-4 turns on, so a refusal
// that misreports what it refused is a guard nobody can audit from its output.
describe("the URL refusals quote what they actually refused", () => {
  it("quotes the ACTUAL port, not a constant", () => {
    for (const port of ["8080", "9999", "1"]) {
      const r = assertAllowedNodeUrl(`https://xrplcluster.com:${port}/`);
      expect(r.ok, `port ${port} must be refused`).toBe(false);
      if (!r.ok) {
        expect(r.code).toBe("NODE_URL_NOT_ALLOWED");
        expect(r.message, `port ${port}`).toContain(`used port ${port},`);
      }
    }
  });

  it("quotes the ACTUAL scheme, not a constant", () => {
    for (const [url, scheme] of [
      ["http://xrplcluster.com/", "http:"],
      ["ftp://xrplcluster.com/", "ftp:"],
      ["ws://xrplcluster.com/", "ws:"],
    ] as const) {
      const r = assertAllowedNodeUrl(url);
      expect(r.ok, `${url} must be refused`).toBe(false);
      if (!r.ok) {
        expect(r.code).toBe("NODE_URL_NOT_ALLOWED");
        expect(r.message, url).toContain(`used ${scheme} rather than https`);
      }
    }
  });
});
