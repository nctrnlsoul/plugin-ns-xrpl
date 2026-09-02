// D1. The published tarball shipped dist/tsconfig.tsbuildinfo, 163.4 kB, 57% of
// the unpacked package. There was already a check for exactly that, and it could
// never fire.
//
// Two separate defects, and the second is the one that matters:
//
//   1. tsconfig.json sets outDir "dist" with composite and incremental, and
//      --noEmit does NOT suppress the buildinfo. So `bun run typecheck`, and
//      `bun run check.ts`, and any editor running tsserver, all wrote the file
//      straight into the directory package.json ships. There is no prepack or
//      prepare script, so npm publish shipped whatever was sitting there.
//
//   2. checks/package_entries.ts ran `bun run build` BEFORE it looked, and
//      build.ts deletes dist. The guard cleaned its own subject before measuring
//      it, reported 16 files / 121.5 kB, and exited 0, against a tree where
//      npm pack listed 17 files / 284.9 kB including the buildinfo.
//
// So this file pins the behaviour, not the source text: run the real typecheck
// and look at what lands, and run the real guard against a contaminated tree and
// demand it fails.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { listingMentions, scanPackListing } from "../../checks/pack_listing.ts";

const ROOT = join(import.meta.dirname, "..", "..");
const DIST = join(ROOT, "dist");
const WIN = process.platform === "win32";

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(full));
    else out.push(full);
  }
  return out;
}

describe("build metadata never reaches the output directory", () => {
  it("running the package's own typecheck leaves no .tsbuildinfo under dist/", () => {
    // The exact command that produced the defect. `bun run typecheck` is
    // documented in the README, is the first step of `bun run verify`, and is
    // the first step of check.ts.
    // TypeScript's own JS entry point through node, for the reasons build.ts
    // records: `npx tsc` resolves a decoy package, and Bun's shell cannot run
    // the Windows .cmd shim.
    const r = spawnSync(process.execPath, [
      join(ROOT, "node_modules", "typescript", "lib", "tsc.js"),
      "--noEmit",
      "--project",
      join(ROOT, "tsconfig.json"),
    ]);
    // Rule 95: prove the setup reached the state it claims. If tsc never ran, no
    // build info would appear and the sweep below would pass having tested
    // nothing.
    expect(
      r.status,
      `typecheck must succeed for this test to mean anything:\n${r.stdout}${r.stderr}`,
    ).toBe(0);

    const stray = filesUnder(DIST).filter((f) => f.toLowerCase().includes("tsbuildinfo"));
    try {
      expect(
        stray,
        `tsc wrote build metadata into the directory package.json ships:\n${stray.join("\n")}`,
      ).toHaveLength(0);
    } finally {
      // Remove whatever this test's own failure produced.
      //
      // MEASURED, not defensive. Under checks/mutations.ts this test runs with
      // tsconfig.json deliberately pointed back at dist, so it CREATES the exact
      // artifact it asserts against. Left behind, that artifact fails this test
      // on every LATER mutation, and each of those is then reported "caught" for
      // a reason that has nothing to do with the mutation. A harness that goes
      // red for the wrong reason certifies guards it never tested, which is the
      // one thing it exists to prevent.
      for (const file of stray) rmSync(file, { force: true });
    }
  });

  it("tsconfig.json sends the build info somewhere package.json does not ship", () => {
    const cfg = readFileSync(join(ROOT, "tsconfig.json"), "utf8");
    const match = cfg.match(/"tsBuildInfoFile"\s*:\s*"([^"]+)"/);
    expect(match?.[1], "tsconfig.json must name a tsBuildInfoFile explicitly").toBeDefined();

    const target = (match?.[1] ?? "").replace(/^\.\//, "");
    const shipped: string[] = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).files;
    for (const entry of shipped) {
      expect(
        target.startsWith(entry.replace(/^\.\//, "")),
        `tsBuildInfoFile "${target}" sits inside shipped path "${entry}"`,
      ).toBe(false);
    }
  });

  it("npm publish cannot ship a stale tree, because prepublishOnly rebuilds", () => {
    // npm does not rebuild on its own. Without this hook the tarball is whatever
    // happens to be in dist at the moment of publish.
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    expect(pkg.scripts?.prepublishOnly, "package.json must declare prepublishOnly").toBeTruthy();
  });
});

// F5. Measured by a cold verification pass: every import of @elizaos/core in
// shipped source is `import type`, and the built bundle imports nothing but
// node:crypto. It was nevertheless declared under `dependencies` at an exact
// prerelease pin, so every consumer resolved a beta this package never loads,
// and the exact pin could conflict with the host agent's own copy of the very
// package that is loading this plugin.
//
// A plugin does not depend on its host. The host provides it. That is what
// peerDependencies means.
describe("the dependency surface a consumer inherits", () => {
  const pkg = () => JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

  it("does not force @elizaos/core into a consumer's tree as a hard dependency", () => {
    expect(
      pkg().dependencies?.["@elizaos/core"],
      "the host supplies the runtime, so this must not be a hard dependency",
    ).toBeUndefined();
  });

  it("declares @elizaos/core as a PEER, so the host's own copy is used", () => {
    expect(pkg().peerDependencies?.["@elizaos/core"]).toBeTruthy();
  });

  it("keeps the exact version the runtime findings were measured against, for our own tests", () => {
    // X-002 and X-003 were measured by running AgentRuntime from 2.0.3-beta.7.
    // src/__tests__/runtime-integration.test.ts still drives it. Our own tests
    // pin exactly; consumers must not be pinned to the same beta.
    const p = pkg();
    expect(p.devDependencies?.["@elizaos/core"]).toBe("2.0.3-beta.7");
    expect(
      p.peerDependencies?.["@elizaos/core"],
      "a consumer must not be pinned to one beta build",
    ).not.toBe("2.0.3-beta.7");
  });

  it("the peer range still admits the measured build, and is not open-ended across majors", () => {
    const range = String(pkg().peerDependencies?.["@elizaos/core"] ?? "");
    expect(range, "must not exclude the version we measured").toContain("2.0.3-beta.7");
    expect(
      range,
      "must stop before the next major, or a 3.x breaking change is silently in range",
    ).toMatch(/<\s*3\.0\.0/);
  });

  it("every import of @elizaos/core in shipped source is types-only", () => {
    // This is what makes the peer declaration safe rather than optimistic. A
    // value import would make the bundle fail to load without the host present,
    // and nothing else in the suite would notice.
    for (const rel of ["src/plugin.ts", "src/provider.ts"]) {
      const src = readFileSync(join(ROOT, rel), "utf8");
      const imports = [...src.matchAll(/^import\s+(type\s+)?[^;]*?from\s+"@elizaos\/core";$/gm)];
      // Rule 95: prove the setup. A file that stopped importing it at all would
      // pass a loop over an empty list.
      expect(imports.length, `${rel} must import @elizaos/core for this to test anything`).toBe(1);
      expect(imports[0]?.[1], `${rel} must use \`import type\`: ${imports[0]?.[0]}`).toBeDefined();
    }
  });
});

// The export surface a CONSUMER actually gets. Found unasserted by a cold pass:
// deleting the whole turn cache export block from src/index.ts left the suite
// green at 361, because every test imports ../core/turncache.ts directly. A
// consumer cannot do that. It has the package entry point and nothing else, and
// src/index.ts says in its own header that the pure core is exported so it can
// be tested, reused and audited without standing up a runtime.
describe("the public entry point re-exports the pure core it claims to", () => {
  it("exports the turn cache, and the SAME bindings the provider itself uses", async () => {
    const index = (await import("../index.ts")) as unknown as Record<string, unknown>;
    const direct = (await import("../core/turncache.ts")) as unknown as Record<string, unknown>;

    const names = [
      "TURN_CACHE_KEY_SEPARATOR",
      "createTurnCache",
      "isUuidLike",
      "readTurnCache",
      "turnCacheKey",
      "writeTurnCache",
    ];
    // Rule 95: a loop over an empty list passes vacuously.
    expect(names.length).toBeGreaterThan(0);

    for (const name of names) {
      expect(index, `src/index.ts must export ${name}`).toHaveProperty(name);
      expect(direct[name], `setup: ${name} must exist in the module`).toBeDefined();
      // Identity, not merely presence. A re-export that resolved to some other
      // binding would satisfy toHaveProperty and be a different function.
      expect(index[name], `${name} must be the module's own binding`).toBe(direct[name]);
    }
  });
});

describe("the pack listing scanner", () => {
  const CLEAN = [
    "npm notice 1.1kB LICENSE",
    "npm notice 3.9kB README.md",
    "npm notice 25.4kB dist/index.js",
    "npm notice 2.1kB package.json",
  ].join("\n");

  it("passes a clean listing", () => {
    expect(scanPackListing(CLEAN, "test")).toHaveLength(0);
  });

  it("FLAGS the exact line that shipped: dist/tsconfig.tsbuildinfo", () => {
    const problems = scanPackListing(
      `${CLEAN}\nnpm notice 163.4kB dist/tsconfig.tsbuildinfo`,
      "test",
    );
    expect(problems).toHaveLength(1);
    // Fail for the reason it names, not merely fail.
    expect(problems[0]).toContain("tsbuildinfo");
    expect(problems[0]).toContain("not a deliverable");
  });

  it("flags a frontend, a dotenv and a key, each on its own", () => {
    for (const [line, needle] of [
      ["npm notice 1kB dist/index.html", "index.html"],
      ["npm notice 1kB .env", ".env"],
      ["npm notice 1kB dist/server.pem", ".pem"],
      ["npm notice 1kB dist/react-shim.js", "react"],
    ] as const) {
      const problems = scanPackListing(`${CLEAN}\n${line}`, "test");
      expect(problems.length, line).toBeGreaterThan(0);
      expect(problems.join(" "), line).toContain(needle);
    }
  });

  it("only reads npm notice FILE lines, so prose cannot trip or hide it", () => {
    expect(
      listingMentions("tsbuildinfo appears here but not on a notice line", "tsbuildinfo"),
    ).toBe(false);
    expect(listingMentions("npm notice 1kB dist/tsconfig.tsbuildinfo", "tsbuildinfo")).toBe(true);
  });

  it("escapes every regex metacharacter in a term, not just the first dot", () => {
    // ".env" must not match "aXenv". The original escaped one dot and left the
    // rest live, which is harmless for today's terms and wrong for tomorrow's.
    expect(listingMentions("npm notice 1kB dist/aXenv.js", ".env")).toBe(false);
    expect(listingMentions("npm notice 1kB dist/.env", ".env")).toBe(true);
  });
});

describe("the package guard measures the tree it is HANDED", () => {
  it("fails on a contaminated dist without being allowed to rebuild it first", () => {
    // The defect in one test. Plant the exact file that shipped, then run the
    // real guard. It must fail, and it must fail BEFORE the build that would
    // have erased the evidence.
    const planted = join(DIST, "tsconfig.tsbuildinfo");
    const distExisted = existsSync(DIST);
    if (!distExisted) mkdirSync(DIST, { recursive: true });
    const plantedExisted = existsSync(planted);

    try {
      writeFileSync(planted, "planted by package-surface.test.ts", "utf8");
      const r = spawnSync("bun", [join(ROOT, "checks", "package_entries.ts")], {
        cwd: ROOT,
        encoding: "utf8",
        shell: WIN,
      });
      const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;

      expect(r.status, `the guard must reject a contaminated tree. output:\n${out}`).not.toBe(0);
      expect(out).toContain("tsbuildinfo");
      // Proves the ordering, which is the actual fix: the file was still there
      // when the guard looked, so the guard cannot have rebuilt first.
      expect(out).toMatch(/as handed|WORKING TREE/i);
    } finally {
      if (!plantedExisted && existsSync(planted)) rmSync(planted, { force: true });
      if (!distExisted && existsSync(DIST)) rmSync(DIST, { recursive: true, force: true });
    }
  });
});
