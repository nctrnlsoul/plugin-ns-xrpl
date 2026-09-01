# CLAUDE.md

**This file is security-critical code.** An insecure instruction here is executed
faithfully by every future session, without anyone reviewing it again. The
documented real case: a `CLAUDE.md` told an agent to embed an API key in source
and "protect" it with a Caesar cipher, and the agent complied. Review changes to
this file with the same force as changes to a validator.

Keep it short. Every line below is a constraint, not a preference.

---

## What this package is

`@northschema/plugin-xrpl` reads public XRPL ledger state for elizaOS agents.
One provider, read-only. Balances and trust lines from a pinned public node.

## The one finding that shapes everything

**On this runtime, `throw` is fail-OPEN.**

Measured against `@elizaos/core` 2.0.3-beta.7 by running `AgentRuntime`
(`runtime.ts` 3794-3865 and 3932-3945), not by reading its types:

| a provider that... | the runtime does |
|---|---|
| throws | catches, logs, substitutes `{text:"",values:{},data:{}}` |
| returns `undefined`, `{}`, or `{text:null}` | same |
| hangs | abandons it at 30,000ms, same. Measured at 30,027ms |

`composeState` then builds the prompt only from provider texts that are non-empty
after `trim()`. **Every one of those contributes zero characters.** No error, no
marker, nothing. The model answers the user's XRPL question from its own priors,
and nothing in the prompt says the lookup failed.

So the usual instinct is exactly wrong here. Rule 10 still holds and malformed
input still BLOCKS, but:

> **A BLOCK has to be SPOKEN. Never thrown, never empty, and never late.**

Reproduce it: `src/__tests__/runtime-integration.test.ts`, which drives the real
runtime and includes a positive control asserting a throwing provider is erased
completely.

## Invariants. Do not break these without changing the tests that name them.

1. **The provider never throws.** Every path returns a `ProviderResult`. The
   outer `catch` in `src/provider.ts` is the last line of defence and is
   exercised by tests that force a throw from inside `run()`.
2. **Every attempted lookup that does not succeed returns non-empty text.**
   Empty text is permitted in exactly one case: no XRPL address was present in
   the message, so nothing was attempted.
3. **Every refusal arrives inside `BOUNDS.TOTAL_LOOKUP_BUDGET_MS`.** A refusal
   produced after the runtime's 30,000ms cutoff is discarded as completely as a
   thrown one. Per-request timeouts alone are not enough: one lookup makes up to
   four requests.
4. **Zero signing surface.** No seed handling, no key material, no transaction
   submission, no actions array entries. If a payment path is ever wanted, that
   is a different package and a different security review, not an increment of
   this one.
5. **The node URL is a pinned constant** (`src/core/node-url.ts`) and the plugin
   declares no `pluginParameters`. Nothing reads it from environment, character
   config, or conversation. If it ever becomes configurable it needs the
   allowlist in front of it, and never a value from conversation. Unpinned plus
   conversation-sourced is SSRF.
   - The outbound URL is **rebuilt from validated components**, never passed
     through. That is what stops userinfo reaching `fetch` even if the
     credential branch is weakened. A URL carrying a credential sends it.
   - `isNeverAValidNodeHost` runs **before** the allowlist and is exported so it
     can be tested directly. Two earlier versions of that logic sat below the
     allowlist where no input could reach them.
   - Known limit: the hostname is checked, not the address DNS resolves it to.
6. **Raw responses are validated before anything shapes them.** Transport returns
   the parsed body untouched; `src/core/response.ts` decides what it means. A
   guard downstream of a coercion is not a guard.
7. **Never default an absent value.** There is no correct default for a balance.
   `?? 0`, `?? []`, `|| 0` and friends are banned on any deciding path and
   `checks/failopen_lint.ts` fails the build on them. A genuine `"0"` is real
   data and must survive.
8. **Ledger content is never decoded and never rendered as prose.** Trust line
   currency codes are rendered as hex or as three plain alphanumerics, never
   decoded to ASCII: a 40-hex code carries 20 attacker-chosen bytes. Values are
   rendered as labelled `key: value` data lines under a header saying they are
   data and not instructions.
9. **Never read Memos, the account `Domain` field, or NFT `URI`.** The channel is
   removed rather than filtered.
10. **Truncation is always spoken.** Any omitted trust line, for any reason, is
    counted and reported. A shortened list must never read as a complete one.
    This holds one level up too: a message may name several addresses and only
    the FIRST is ever looked up, so the rest are counted and stated as
    `other_addresses_not_looked_up`, on the success path and on every refusal
    `run()` produces. Threshold of one, and DISTINCT strings, because
    overstating an omission is the same inaccuracy as hiding one. That was D6,
    and it was the last omission here that said nothing.
    - One deliberate exception, and it must stay one: the outer `catch` in
      `src/provider.ts` passes zero, because `run()` can throw before it has
      read the message at all. Saying nothing about other addresses is the only
      claim that branch can support. Do not "fix" it into reporting a count
      nothing measured.
11. **No secrets, ever.** This package has no API key, no environment variable
    and no `.env`. If that ever changes, the value lives in an OS environment
    variable and is never pasted into chat, a command, or a file.

## Commands

```
bun run verify     typecheck, lint, tests, bun audit, the gate, then package:check
bun run check.ts   the development gate on its own
bun scripts/live-check.mjs   the real network path, run deliberately
```

`verify` has SIX steps, not five, and it ends with `package:check`. That is the
publish-relevant one: it reads the `npm pack` listing of the tree as handed,
rebuilds `dist`, and reads the listing again, so the tarball is measured rather
than assumed. `prepublishOnly` runs the whole of `verify`, so all six fire at the
door on any publish, local or from CI. The audit step is `bun audit`, not
`npm audit`.

The gate is `check.ts` plus `checks/`. Install the hook once:

```
git config core.hooksPath .githooks
```

`check.ts` reports whether that has actually been done, because a hook nobody
installed is a hook that has never run.

## What an adversarial pass found, and the rule it earned

Eleven guards were handed to agents that had not written them, briefed with the
requirement and the words *make this go red*. They returned **46 independently
reproduced holes**: source edits that broke a stated requirement while the whole
suite stayed green. Only the address checksum came back clean.

The shipped behaviour was correct in almost every case. The **tests** were not
pinning it. One shape explains nearly all 46:

> **A guard pinned by ONE example is pinned by nothing.** Any weakening that
> still rejects that single example survives.

Concretely, and each of these was live in this repo:

- The only credential test used `https://user:pass@host/`, which sets **both**
  halves of the userinfo. Swapping `||` for `&&` stayed green while
  `https://sk_live_ABC@host/` was allowed and the secret went out in an
  `Authorization` header.
- Every truncation notice was pinned with a large number (500 lines, 4,000 not
  retrieved). Every `> 0` could become `> 1`, so omitting **exactly one** line
  went unreported.
- `validated` was pinned by `false` and `undefined`. Both are falsy, so a
  truthiness check passed; and setting a key to `undefined` **creates** an own
  property, so absence was never actually tested.
- The never-decode rule was pinned by asserting three words from one payload
  were absent. Nothing asserted the positive property that the output is only
  hex digits.

Three rules follow, and they are cheap:

1. **A negative test must fail for the REASON it names.** Assert the code or the
   message, not just `ok === false`. Several inputs were being refused by a
   different branch than the one under test.
2. **Test the threshold, not a comfortable example.** The smallest case that
   should trip a notice is one.
3. **Assert the positive property where one exists.** "Does not contain IGNORE"
   is weaker than "contains only `[0-9A-F]`".

A third pass added a fourth. It is about where an audit STARTS, not how hard it
looks.

4. **Enumerate from the SOURCE side, not the test side.** The population is what
   the code EMITS, not what the tests already mention. Starting from the
   assertions can only grade the assertions that exist and cannot see a value
   with no assertion at all: `owner_count` and `account_sequence` appeared
   **zero** times across the whole suite and every file under `checks/`. Both
   rounds above hunted weak assertions here and neither saw them. 46 emitted
   values, 15 survivors. Nothing in `bun run verify` does this for you.

**The corollary the three above miss: a refusal message IS report content.**
Eleven of the fifteen were there, never audited as output because it does not
look like the report. It is the only text the model gets when a lookup fails, so
a wrong number in it has no successful report beside it to contradict it.

Two findings were defects in the code rather than in its tests, and both are
worth remembering because neither would fail anything:

- `node-url.ts` **claimed in a comment** to block private and loopback ranges
  and no such code existed. A security file that describes a control it does not
  implement answers the audit on that control's behalf.
- Two layers of IP-literal defence sat **below** the allowlist, where no input
  could reach them. Unreachable defence in depth is not defence in depth. A layer
  that cannot be reached cannot be tested, and is the one that quietly stops
  working.

## Working on this

- **Tests before implementation** for anything in `src/core/` or `src/provider.ts`.
  Every row of the security pass fail-closed table is a test before it is code.
- **A new guard is not done until a mutation proves it.** Add an entry to
  `checks/mutations.ts` that reintroduces the bug and demand the suite go red. A
  survivor means the guard is decorative. That harness found a real survivor
  within minutes of existing: the provider's outer `catch` had no test.
- **Never write literal invisible or control characters into source.** Use `\u`
  escapes. Literal ones broke `src/core/render.ts` and the lint now fails on
  them.
- **The live check is not in the gate** and it earns its keep anyway. It found
  that real ledger balances use exponent form (`-4263500000000000e-27`), which no
  unit test had, and which was refusing legitimate accounts.

## What this package deliberately does not do

Read-only is one mitigation, not a conclusion. Say that out loud in any handoff:
a green demo is not a safe product, and "read-only" is not a synonym for "safe".
