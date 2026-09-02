// The test that proves the item 0 fix WHERE IT ACTUALLY TAKES EFFECT.
//
// Every other test in this suite asserts on what the provider returns. That is
// not the same fact as what the model sees, and the gap between those two is
// exactly the finding: composeState drops any provider text that is empty after
// trim, so a provider can return a perfectly good refusal object and still
// contribute nothing to the prompt.
//
// So this drives the real AgentRuntime from @elizaos/core 2.0.3-beta.7 with the
// real plugin registered, and reads the refusal back out of state.text. Grep the
// artifact, not the note about the artifact.
//
// The CONTROL provider is load-bearing. If its marker is missing from
// state.text, the rig is broken and the assertions about our provider are void.

import { randomUUID } from "node:crypto";
import {
  AgentRuntime,
  ChannelType,
  DefaultMessageService,
  type IAgentRuntime,
  InMemoryDatabaseAdapter,
  MemoryType,
  ModelType,
  type Provider,
} from "@elizaos/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createXrplProvider } from "../provider.ts";

const ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const CONTROL_MARKER = "CONTROL_PROVIDER_REACHED_THE_PROMPT";

let runtime: IAgentRuntime | undefined;

afterEach(async () => {
  await runtime?.stop();
  runtime = undefined;
});

async function composeWith(fetchImpl: unknown, text: string) {
  const id = randomUUID() as `${string}-${string}-${string}-${string}-${string}`;
  const character = {
    name: "XRPL Test Agent",
    bio: ["test"],
    system: "test",
    templates: {},
    plugins: [],
    knowledge: [],
    secrets: {},
    settings: {},
    messageExamples: [],
    postExamples: [],
    topics: [],
    adjectives: [],
    style: { all: [], chat: [], post: [] },
    id,
  };

  runtime = new AgentRuntime({
    agentId: id,
    character,
    adapter: new InMemoryDatabaseAdapter(),
    enableDocuments: false,
    enableRelationships: false,
    enableTrajectories: false,
    plugins: [
      {
        name: "xrpl-under-test",
        description: "the plugin under test plus a control",
        providers: [
          createXrplProvider({ fetchImpl: fetchImpl as never }),
          {
            name: "CONTROL",
            description: "proves the rig reads the prompt",
            get: async () => ({ text: CONTROL_MARKER, values: {}, data: {} }),
          },
        ],
      },
    ],
  } as never);

  await runtime.initialize();

  const message = {
    id: randomUUID(),
    roomId: randomUUID(),
    entityId: randomUUID(),
    agentId: runtime.agentId,
    content: { text, channelType: ChannelType.GROUP },
    createdAt: Date.now(),
    metadata: { type: MemoryType.MESSAGE },
  };

  const state = await runtime.composeState(message as never);
  return String(state.text ?? "");
}

describe("the refusal survives the real runtime and reaches the prompt", () => {
  it("a node failure is VISIBLE in state.text, not swallowed into silence", async () => {
    const prompt = await composeWith(async () => {
      throw new Error("ECONNREFUSED");
    }, `what is the balance of ${ADDR}`);

    // Control first. If this fails nothing else in this test means anything.
    expect(prompt, "rig control: the control provider must reach the prompt").toContain(
      CONTROL_MARKER,
    );

    // The finding, inverted into a guarantee: our refusal is in the prompt.
    //
    // F2 audit: this asserted toContain("XRPL"), and the character above is
    // named "XRPL Test Agent", so the prompt carries "XRPL" whether or not this
    // provider contributed anything. The assertion has to name the sentence
    // only this provider can produce.
    expect(prompt.toLowerCase()).toMatch(/could not|unable|failed|refus/);
    expect(prompt, "the provider's own refusal, not the character's name").toContain(
      "XRPL lookup refused.",
    );
  });

  it("a malformed address refusal is VISIBLE in state.text", async () => {
    const prompt = await composeWith(
      () => {
        throw new Error("must not be called");
      },
      // Valid charset, bad checksum: rippled called this actMalformed.
      "look up rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk for me",
    );
    expect(prompt).toContain(CONTROL_MARKER);
    expect(prompt.toLowerCase()).toMatch(/address|refus|could not|unable/);
  });

  it("PROOF OF THE FAILURE MODE: a throwing provider contributes nothing at all", async () => {
    // The positive control for the finding itself. This registers a provider
    // that throws the way a naive implementation would, and asserts the runtime
    // erases it completely. If this ever starts failing, ElizaOS changed its
    // behaviour and the spoken-refusal contract can be revisited.
    const id = randomUUID() as `${string}-${string}-${string}-${string}-${string}`;
    runtime = new AgentRuntime({
      agentId: id,
      character: {
        name: "T",
        bio: ["b"],
        system: "s",
        templates: {},
        plugins: [],
        knowledge: [],
        secrets: {},
        settings: {},
        messageExamples: [],
        postExamples: [],
        topics: [],
        adjectives: [],
        style: { all: [], chat: [], post: [] },
        id,
      },
      adapter: new InMemoryDatabaseAdapter(),
      enableDocuments: false,
      enableRelationships: false,
      enableTrajectories: false,
      plugins: [
        {
          name: "naive",
          description: "the implementation this project deliberately does not ship",
          providers: [
            {
              name: "NAIVE_THROWER",
              description: "throws on failure, the obvious and wrong choice",
              get: async () => {
                throw new Error("XRPL_LOOKUP_FAILED_SENTINEL");
              },
            },
            {
              name: "CONTROL",
              description: "control",
              get: async () => ({ text: CONTROL_MARKER, values: {}, data: {} }),
            },
          ],
        },
      ],
    } as never);
    await runtime.initialize();

    const state = await runtime.composeState({
      id: randomUUID(),
      roomId: randomUUID(),
      entityId: randomUUID(),
      agentId: runtime.agentId,
      content: { text: "anything", channelType: ChannelType.GROUP },
      createdAt: Date.now(),
      metadata: { type: MemoryType.MESSAGE },
    } as never);

    const prompt = String(state.text ?? "");
    expect(prompt, "control must survive").toContain(CONTROL_MARKER);
    expect(prompt, "the thrown sentinel must be entirely absent").not.toContain(
      "XRPL_LOOKUP_FAILED_SENTINEL",
    );
    expect(prompt.toLowerCase()).not.toContain("error");
  });
});

// ---------------------------------------------------------------------------
// STAGE 1. Where the report lands, which the composeState tests above cannot
// see.
//
// ElizaOS answers in two stages. Stage 1 (RESPONSE_HANDLER) has its prompt built
// by composeResponseState, which composes a FIXED list of providers plus whatever
// declares alwaysInResponseState. Stage 2 (ACTION_PLANNER) is where an ordinary
// provider runs, and depending on what stage 1 produces the runtime may or may
// not go on to run that second stage.
//
// So the flag's guarantee is narrow and these tests pin exactly it and nothing
// wider: the report is composed into the stage-1 response state whichever
// contexts the turn selects. Nothing below claims the provider would otherwise go
// unasked, or anything about what the model would answer.
//
// This drives the REAL stage 1: DefaultMessageService.handleMessage, with a
// stub RESPONSE_HANDLER model that records the prompt it is handed. What is
// asserted is the report text inside that prompt, not a property on an object.
// ---------------------------------------------------------------------------

const ACCOUNT_INFO_OK = {
  result: {
    account_data: {
      Account: ADDR,
      Balance: "56774133566",
      OwnerCount: 1,
      Sequence: 44196,
      LedgerEntryType: "AccountRoot",
    },
    ledger_index: 106661700,
    validated: true,
    status: "success",
  },
};

const LINES_OK = {
  result: { account: ADDR, lines: [], ledger_index: 106661700, validated: true, status: "success" },
};

/**
 * Run one real turn and return the prompt stage 1 was given.
 *
 * `shape` receives the provider this package actually ships and returns the one
 * to register, so the negative control differs from the shipped object in
 * exactly one field and nothing else.
 */
async function stage1Prompt(shape: (p: Provider) => Provider) {
  const fetchImpl = vi.fn(async (_u: unknown, init?: { body?: string }) => {
    const method = String(JSON.parse(String(init?.body ?? "{}")).method ?? "");
    const body = method === "account_info" ? ACCOUNT_INFO_OK : LINES_OK;
    return new Response(JSON.stringify(body), { status: 200 });
  });
  const prompts: string[] = [];
  const id = randomUUID() as `${string}-${string}-${string}-${string}-${string}`;

  runtime = new AgentRuntime({
    agentId: id,
    character: {
      name: "T",
      bio: ["b"],
      system: "s",
      templates: {},
      plugins: [],
      knowledge: [],
      secrets: {},
      settings: {},
      messageExamples: [],
      postExamples: [],
      topics: [],
      adjectives: [],
      style: { all: [], chat: [], post: [] },
      id,
    },
    adapter: new InMemoryDatabaseAdapter(),
    enableDocuments: false,
    enableRelationships: false,
    enableTrajectories: false,
    plugins: [
      {
        name: "xrpl-under-test",
        description: "the plugin under test plus a control",
        providers: [
          shape(createXrplProvider({ fetchImpl: fetchImpl as never })),
          {
            name: "STAGE1_CONTROL",
            description: "proves the rig reads the stage-1 prompt",
            alwaysInResponseState: true,
            get: async () => ({ text: CONTROL_MARKER, values: {}, data: {} }),
          },
        ],
        models: {
          [ModelType.RESPONSE_HANDLER]: async (_rt: unknown, params: unknown) => {
            prompts.push(JSON.stringify(params));
            return { text: "ok" };
          },
          [ModelType.TEXT_LARGE]: async () => "ok",
          [ModelType.TEXT_SMALL]: async () => "ok",
        },
      },
    ],
  } as never);

  await runtime.initialize();

  await new DefaultMessageService().handleMessage(
    runtime as never,
    {
      id: randomUUID(),
      roomId: randomUUID(),
      entityId: randomUUID(),
      agentId: runtime.agentId,
      content: { text: `what is the balance of ${ADDR}`, channelType: ChannelType.GROUP },
      createdAt: Date.now(),
      metadata: { type: MemoryType.MESSAGE },
    } as never,
    (async () => []) as never,
    { responseId: randomUUID() } as never,
  );

  return { prompts, fetchImpl };
}

describe("the provider reaches the STAGE 1 router prompt, not only the planner's", () => {
  it("the report is IN the prompt the router is given", async () => {
    const { prompts, fetchImpl } = await stage1Prompt((p) => p);

    // Rig control first. If stage 1 was never reached, or its prompt carries no
    // provider text at all, nothing below means anything.
    expect(prompts, "stage 1 must have run exactly once").toHaveLength(1);
    const prompt = prompts[0] ?? "";
    expect(prompt, "rig control: a flagged provider must reach the stage-1 prompt").toContain(
      CONTROL_MARKER,
    );

    // The claim. Not "the address appears": the user's own message carries the
    // address, so that would pass with the provider switched off entirely. These
    // are strings only this provider's report can produce.
    expect(prompt, "the router must be given the report, not just the question").toContain(
      "XRPL account report",
    );
    expect(prompt).toContain("xrp_balance_drops: 56774133566");
    expect(fetchImpl, "the lookup really ran").toHaveBeenCalled();
  });

  it("NEGATIVE CONTROL: without the flag the same report is ABSENT and nothing is looked up", async () => {
    // One field different from the object above, and nothing else.
    const { prompts, fetchImpl } = await stage1Prompt((p) => ({
      ...p,
      alwaysInResponseState: false,
    }));

    expect(prompts).toHaveLength(1);
    const prompt = prompts[0] ?? "";
    expect(prompt, "the rig still reads the prompt").toContain(CONTROL_MARKER);
    expect(prompt, "the router gets no report at all").not.toContain("XRPL account report");
    expect(prompt).not.toContain("xrp_balance_drops");
    expect(
      fetchImpl,
      "without the flag the provider is not even asked during stage 1",
    ).not.toHaveBeenCalled();
  });

  it("NEGATIVE CONTROL: `private` cancels the flag, which is why it is never set", async () => {
    // Measured in @elizaos/core 2.0.3-beta.7: alwaysOnResponseStateProviderNames
    // requires `alwaysInResponseState && name && !provider.private`. A private
    // provider with the flag set is silently dropped from stage 1, and nothing
    // reports it.
    const { prompts } = await stage1Prompt((p) => ({ ...p, private: true }));
    const prompt = prompts[0] ?? "";
    expect(prompt).toContain(CONTROL_MARKER);
    expect(prompt, "private wins over the flag").not.toContain("XRPL account report");
  });
});
