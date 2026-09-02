// The publish workflow is new infrastructure with a way to fail SILENTLY, so it
// is held to the same rule as everything else here.
//
// npm attaches a provenance attestation only when four things hold, and it does
// not fail loudly on all four. A publish that quietly ships with no attestation
// looks exactly like one that shipped with a good one, which is the shape this
// repo has been burned by twice: a control that reports on its own behalf.
//
// The four, each asserted below and each broken by an entry in
// checks/mutations.ts:
//
//   1. the OIDC id-token permission is granted as `write`
//   2. the runner is cloud-hosted
//   3. the gate runs BEFORE the publish step
//   4. `--provenance` is not on the command line, because publishConfig sets it
//
// Two more blocks below are about AUTHENTICATION rather than attestation, and
// the first of them is an INVERSION. npm now authenticates this workflow as a
// registered trusted publisher, so:
//
//   5. no registry token, anywhere in the file. What was once the thing to
//      assert PRESENT is now a regression to assert ABSENT
//   6. npm is raised to the 11.5.1 that trusted publishing requires, and the
//      job REFUSES below that floor instead of reporting a version
//
// THE METHOD MATTERS MORE THAN THE LIST. Commit 3829264 established that
// asserting a SHAPE appears in a file is not asserting the thing is configured,
// and found three ways to satisfy a shape check while the guard never runs. Two
// of those three apply verbatim to YAML, so the real workflow file carries both
// traps deliberately rather than in a synthetic fixture:
//
//   - it mentions the provenance flag in a COMMENT, so a check that greps the
//     file rather than the parsed run commands fails on a correct file
//   - it mentions the publish step in PROSE above the verify step, so a check
//     that compares text positions concludes publish comes first. Measured:
//     the first "publish" is at offset 173 and "bun run verify" at 2458.
//
// So everything below reads the file with comments stripped and measures
// ordering by STEP INDEX. Both properties are proved against the real artifact,
// not only against a fixture.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "..", "..");
const WORKFLOW = join(ROOT, ".github", "workflows", "publish.yml");

/**
 * GitHub's canonical case for the account that will own this repo.
 *
 * MEASURED, not assumed: `GET https://api.github.com/users/nctrnlsoul` returns
 * `"login": "nctrnlsoul"`. npm compares `repository` against the publishing
 * repo CASE-SENSITIVELY, and a mismatch fails at the door after the gate has
 * already passed, which is the most expensive place to find it.
 */
const OWNER = "nctrnlsoul";
const REPO = "plugin-ns-xrpl";

/** Runner labels GitHub hosts itself. Anything else cannot produce provenance. */
const CLOUD_RUNNERS = [
  "ubuntu-latest",
  "ubuntu-24.04",
  "ubuntu-22.04",
  "macos-latest",
  "windows-latest",
];

/** The flag that must live in package.json and nowhere else. */
const FLAG = "--provenance";

/**
 * The two names the removed token path used.
 *
 * Asserted ABSENT, which is an inversion: until npm's trusted publisher
 * configuration replaced it, this env was the thing to assert present.
 */
const TOKEN_ENV = "NODE_AUTH_TOKEN";
const TOKEN_SECRET = "secrets.NPM_TOKEN";

/**
 * Any repository secret at all, not only the one that used to be here.
 *
 * Rule 2: test the threshold, not the comfortable example. Pinning the exact
 * former name would let `secrets.NPM_TOKEN_2` back in unremarked.
 */
const SECRET_EXPR = /secrets\./;

/** npm states this floor itself: trusted publishing needs npm 11.5.1 or later. */
const NPM_FLOOR = "11.5.1";

/**
 * Blank out YAML comments, leaving line structure intact.
 *
 * A `#` opens a comment only outside quotes and only at the start of a line or
 * after whitespace, so `"a#b"` and `url#frag` survive. Newlines are preserved
 * so every line-based reader below still sees the same line numbers.
 */
function stripYamlComments(src: string): string {
  let out = "";
  let quote: string | null = null;
  let prev = "";
  for (let i = 0; i < src.length; i++) {
    const ch = src[i] as string;
    if (quote !== null) {
      out += ch;
      if (ch === quote) quote = null;
      prev = ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
      prev = ch;
      continue;
    }
    if (ch === "#" && (prev === "" || prev === "\n" || prev === " " || prev === "\t")) {
      while (i < src.length && src[i] !== "\n") i++;
      out += "\n";
      prev = "\n";
      continue;
    }
    out += ch;
    prev = ch;
  }
  return out;
}

function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

/** Every `key: value` directly under a top-level block, e.g. `permissions:`. */
function readTopLevelBlock(src: string, blockName: string): Map<string, string> {
  const found = new Map<string, string>();
  // Any line at indent 0 ends the block, so keys belonging to a LATER top-level
  // block are never attributed to this one.
  let inside = false;
  for (const line of stripYamlComments(src).split("\n")) {
    if (line.trim() === "") continue;
    if (indentOf(line) === 0) {
      inside = line.trim() === `${blockName}:`;
      continue;
    }
    if (!inside) continue;
    const m = line.match(/^\s+([A-Za-z0-9_.-]+):\s*(.*)$/);
    if (m) found.set(m[1] as string, (m[2] as string).trim());
  }
  return found;
}

/** Every `runs-on:` value in the file, comments stripped. */
function readRunsOn(src: string): string[] {
  return stripYamlComments(src)
    .split("\n")
    .map((l) => l.match(/^\s*runs-on:\s*(.+?)\s*$/))
    .filter((m): m is RegExpMatchArray => m !== null)
    .map((m) => (m[1] as string).replace(/^["']|["']$/g, ""));
}

interface Step {
  name: string;
  run: string;
  /**
   * Every line of the step, comments already stripped.
   *
   * `run` alone cannot see a step's `env:` block, and the token this file now
   * asserts is ABSENT lived in one. Rule 4: enumerate from the SOURCE side. A
   * check that can only read run commands cannot report on a key it structurally
   * never looks at, and would pass whatever the step declares.
   */
  body: string;
}

/**
 * The steps of every job, IN ORDER.
 *
 * Order comes from the sequence of `- ` items under `steps:`, which is what
 * GitHub actually executes. It is deliberately not derived from where a string
 * happens to appear in the file.
 */
function readSteps(src: string): Step[] {
  const steps: Step[] = [];
  let stepIndent: number | null = null;
  let current: string[] | null = null;

  const flush = () => {
    if (current === null) return;
    const body = current.join("\n");
    const name = body.match(/(?:^|\n)\s*-?\s*name:\s*(.+?)\s*$/m);
    const inline = body.match(/(?:^|\n)\s*-?\s*run:\s*(.+?)\s*$/m);
    let run = inline ? (inline[1] as string) : "";
    if (run === "|" || run === ">") {
      const after = body.slice((inline?.index ?? 0) + (inline?.[0].length ?? 0));
      run = after
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .join(" ");
    }
    steps.push({ name: name ? (name[1] as string) : "", run, body });
    current = null;
  };

  for (const line of stripYamlComments(src).split("\n")) {
    if (line.trim() === "") continue;
    if (/^\s*steps:\s*$/.test(line)) {
      flush();
      stepIndent = null;
      continue;
    }
    const isItem = /^\s*-\s/.test(line);
    if (isItem && (stepIndent === null || indentOf(line) === stepIndent)) {
      flush();
      stepIndent = indentOf(line);
      current = [line];
      continue;
    }
    if (current !== null && indentOf(line) > (stepIndent ?? 0)) current.push(line);
    else if (current !== null) flush();
  }
  flush();
  return steps;
}

const RAW = readFileSync(WORKFLOW, "utf8");
const STEPS = readSteps(RAW);
const RUN_COMMANDS = STEPS.map((s) => s.run).filter(Boolean);
const PKG = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

const stepRunning = (needle: string): number => STEPS.findIndex((s) => s.run.includes(needle));

/** The step that publishes, from any parse of this file. Throws rather than
 * returning undefined, so an assertion is never made against nothing. */
function publishStepOf(steps: Step[]): Step {
  const found = steps.find((s) => s.run.includes("npm publish"));
  if (found === undefined) throw new Error("no publish step parsed: nothing to assert on");
  return found;
}

/** Whether a step declares an `env:` block, read from the step's own lines. */
const declaresEnv = (step: Step): boolean => step.body.split("\n").some((l) => l.trim() === "env:");

describe("the reader, before anything it reports is believed", () => {
  it("POSITIVE CONTROL: a directive written in a comment is stripped away", () => {
    const stripped = stripYamlComments("permissions:\n  # id-token: write\n  contents: read\n");
    expect(stripped).not.toContain("id-token");
    expect(stripped).toContain("contents: read");
  });

  it("POSITIVE CONTROL: a hash inside quotes is NOT treated as a comment", () => {
    // A stripper that blanks every hash would delete real configuration and
    // turn this file into an alarm that fires on correct workflows.
    expect(stripYamlComments('url: "https://example.com/a#b"')).toContain("a#b");
  });

  it("POSITIVE CONTROL: the step reader keeps declaration order", () => {
    const yaml =
      "jobs:\n  j:\n    steps:\n      - name: A\n        run: a\n      - name: B\n        run: b\n";
    expect(readSteps(yaml).map((s) => s.name)).toStrictEqual(["A", "B"]);
  });

  it("finds the real workflow and parses real steps, so nothing below passes vacuously", () => {
    // Rule 95: prove the setup reached the state it claims. An unparsed file
    // yields zero steps, and every ordering assertion then passes on nothing.
    // Floors low enough that REMOVING a step trips the test named for that
    // removal, not this one. An instrument check that fires on someone else's
    // defect stops being readable as an instrument check.
    expect(RAW.length).toBeGreaterThan(500);
    expect(STEPS.length).toBeGreaterThanOrEqual(5);
    expect(RUN_COMMANDS.length).toBeGreaterThanOrEqual(2);
  });
});

describe("1. the OIDC permission npm needs to sign an attestation", () => {
  it("grants id-token as write", () => {
    expect(readTopLevelBlock(RAW, "permissions").get("id-token")).toBe("write");
  });

  it("NEGATIVE CONTROL: an id-token line written as a comment does not satisfy it", () => {
    const commented = RAW.replace("  id-token: write", "  # id-token: write");
    expect(readTopLevelBlock(commented, "permissions").get("id-token")).toBeUndefined();
  });

  it("grants contents as read, so the token is not wider than the job needs", () => {
    expect(readTopLevelBlock(RAW, "permissions").get("contents")).toBe("read");
  });
});

describe("2. the runner has to be cloud-hosted or npm produces nothing", () => {
  it("names exactly one runner and it is one GitHub hosts", () => {
    const runners = readRunsOn(RAW);
    expect(runners).toHaveLength(1);
    expect(CLOUD_RUNNERS).toContain(runners[0]);
  });

  it("NEGATIVE CONTROL: a self-hosted runner is refused for the reason it names", () => {
    const selfHosted = RAW.replace("runs-on: ubuntu-latest", "runs-on: self-hosted");
    const runners = readRunsOn(selfHosted);
    expect(runners).toStrictEqual(["self-hosted"]);
    expect(CLOUD_RUNNERS).not.toContain(runners[0]);
  });
});

describe("3. the gate runs BEFORE the irreversible step", () => {
  it("the verify step and the publish step both exist and are distinct", () => {
    // Without this, "verify comes before publish" is satisfied by a missing
    // step in a way that reads as an ordering failure rather than an absence.
    expect(stepRunning("bun run verify")).toBeGreaterThanOrEqual(0);
    expect(stepRunning("npm publish")).toBeGreaterThanOrEqual(0);
    expect(stepRunning("bun run verify")).not.toBe(stepRunning("npm publish"));
  });

  it("verify sits at a LOWER STEP INDEX than publish", () => {
    expect(stepRunning("bun run verify")).toBeLessThan(stepRunning("npm publish"));
  });

  it("NEGATIVE CONTROL: this file really does defeat a text-position check", () => {
    // Not hypothetical. The workflow discusses the publish step in its header
    // comment, so an implementation comparing offsets would call a correct file
    // misordered. Asserting the trap is present stops a future edit quietly
    // removing it and making the ordering test weaker than it reads.
    expect(RAW.indexOf("publish")).toBeLessThan(RAW.indexOf("bun run verify"));
  });

  it("the publish step really publishes, so the ordering is about the right step", () => {
    const publish = STEPS[stepRunning("npm publish")];
    expect(publish?.run).toContain("npm publish");
    expect(publish?.run).toContain("--access public");
  });
});

describe("4. provenance is requested in exactly one place", () => {
  it("package.json publishConfig asks for it", () => {
    expect(PKG.publishConfig?.provenance).toBe(true);
  });

  it("no run command passes the flag, so the two sources cannot disagree", () => {
    for (const cmd of RUN_COMMANDS) expect(cmd).not.toContain(FLAG);
  });

  it("NEGATIVE CONTROL: the flag IS in this file, and only in a comment", () => {
    // The positive property, not just an absence: the real artifact contains
    // the string, so a grep-the-file implementation of the test above would go
    // red on a correct workflow. That is what makes stripping load-bearing.
    expect(RAW).toContain(FLAG);
    expect(stripYamlComments(RAW)).not.toContain(FLAG);
  });
});

describe("5. authentication is OIDC, so a registry token here is a REGRESSION", () => {
  // An INVERSION, not a new rule. This env used to be the thing to assert
  // present. npm now authenticates this workflow as a registered trusted
  // publisher, which is also what answers its 2FA requirement, and every CI
  // attempt under the old path died on EOTP because a granular access token
  // cannot answer a 2FA challenge. A token here would now be a long-lived
  // credential the repo does not need, publishing by a route the trusted
  // publisher configuration never authorised.

  it("the publish step declares no env block at all", () => {
    // Rule 4, enumerate from the SOURCE side: assert on what the step DECLARES,
    // not on the one key name that used to be wrong. A check for the name alone
    // reports nothing about an env block holding some other credential.
    expect(declaresEnv(publishStepOf(STEPS))).toBe(false);
  });

  it("no step anywhere reads a repository secret", () => {
    // Whole file, not just the publish step. A job-level env block would
    // authenticate the publish exactly as well while satisfying a check that
    // only ever looks at the publish step.
    expect(stripYamlComments(RAW)).not.toMatch(SECRET_EXPR);
  });

  it("neither name survives stripping, so the env key is pinned as well as the source", () => {
    const stripped = stripYamlComments(RAW);
    expect(stripped).not.toContain(TOKEN_ENV);
    expect(stripped).not.toContain(TOKEN_SECRET);
  });

  it("NEGATIVE CONTROL: both names ARE in this file, and only in comments", () => {
    // The same positive property the --provenance test asserts, for the same
    // reason. The real artifact contains both strings, so a grep-the-file
    // implementation of the three tests above would go red on a correct
    // workflow. That is what makes the stripping load-bearing here too.
    expect(RAW).toContain(TOKEN_ENV);
    expect(RAW).toContain(TOKEN_SECRET);
  });

  it("NEGATIVE CONTROL: putting the env block back trips it, for the reason it names", () => {
    const withToken = RAW.replace(
      "        run: npm publish --access public",
      `        run: npm publish --access public\n        env:\n          ${TOKEN_ENV}: \${{ ${TOKEN_SECRET} }}`,
    );
    // Each detector fires on its own subject, so a failure names which property
    // broke rather than landing on whichever assertion happened to run first.
    expect(declaresEnv(publishStepOf(readSteps(withToken)))).toBe(true);
    expect(stripYamlComments(withToken)).toMatch(SECRET_EXPR);
    expect(stripYamlComments(withToken)).toContain(TOKEN_ENV);
  });
});

describe("6. the runner's npm is raised to what trusted publishing needs", () => {
  // The only precondition in this workflow that belongs to the RUNNER rather
  // than to the repo. npm requires 11.5.1 or later for OIDC, and node-version
  // floats, so what actually lands is decided by GitHub on the day and nothing
  // here can read it. What CAN be pinned is that the workflow raises it, and
  // then refuses below the floor, ahead of the one-way door.

  const npmStep = STEPS.find((s) => s.run.includes("npm install -g"));

  it("a step raises npm, and it runs BEFORE the publish step", () => {
    expect(npmStep).toBeDefined();
    expect(stepRunning("npm install -g")).toBeLessThan(stepRunning("npm publish"));
  });

  it("it also runs before the gate, so a runner below the floor fails in seconds", () => {
    // Not cosmetic. Behind the gate this costs about fifteen minutes and a
    // pushed tag before anyone learns the runner could not have published.
    expect(stepRunning("npm install -g")).toBeLessThan(stepRunning("bun run verify"));
  });

  it("it names the floor npm itself states", () => {
    expect(npmStep?.run).toContain(NPM_FLOOR);
  });

  it("it FAILS the job below the floor rather than only reporting the version", () => {
    // The whole difference between a guard and a log line. A step that runs
    // `npm --version` and prints it satisfies every assertion above and lets
    // the publish go ahead on npm 11.4.2.
    expect(npmStep?.run).toContain("exit 1");
    expect(npmStep?.run).toContain("sort -V");
  });

  it("NEGATIVE CONTROL: dropping the refusal keeps the raise, and is still caught", () => {
    // Proved against the real artifact, not a fixture string: strip the
    // comparison out of this very file and the step still installs npm and
    // still names 11.5.1. Only the `exit 1` assertion above notices.
    const noRefusal = RAW.replace(/\n\s*if \[.*?\n\s*fi\n/s, "\n");
    const step = readSteps(noRefusal).find((s) => s.run.includes("npm install -g"));
    expect(step?.run).toContain(NPM_FLOOR);
    expect(step?.run).not.toContain("exit 1");
  });
});

describe("the workflow fires on the tag that means a release", () => {
  it("triggers on a v-prefixed tag push", () => {
    expect(stripYamlComments(RAW)).toMatch(/on:\s*\n\s*push:\s*\n\s*tags:\s*\n\s*-\s*["']?v\*/);
  });
});

describe("package.json points npm at the repo it will publish from", () => {
  const urls: Array<[string, string]> = [
    ["repository.url", PKG.repository?.url ?? ""],
    ["homepage", PKG.homepage ?? ""],
    ["bugs.url", PKG.bugs?.url ?? ""],
  ];

  it("all three name the same owner and repo", () => {
    for (const [label, url] of urls) {
      expect(url, label).toContain(`github.com/${OWNER}/${REPO}`);
    }
  });

  it("the owner is in GitHub's canonical case, which npm compares exactly", () => {
    // A case-only drift passes every toLowerCase comparison and fails at the
    // registry, after the gate is green and the tag is already pushed.
    for (const [label, url] of urls) {
      // The three URLs end differently: `.git`, `#readme` and `/issues`. The
      // repo segment is whatever sits between the owner and the first of those.
      const seg = url.match(/github\.com\/([^/#?]+)\/([^/#?]+?)(?:\.git)?(?:[/#?]|$)/);
      expect(seg?.[1], `${label} owner segment`).toBe(OWNER);
      expect(seg?.[2], `${label} repo segment`).toBe(REPO);
    }
  });
});
