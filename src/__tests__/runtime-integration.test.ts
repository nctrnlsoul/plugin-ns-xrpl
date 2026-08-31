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
  type IAgentRuntime,
  InMemoryDatabaseAdapter,
  MemoryType,
} from "@elizaos/core";
import { afterEach, describe, expect, it } from "vitest";
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
    expect(prompt.toLowerCase()).toMatch(/could not|unable|failed|refus/);
    expect(prompt).toContain("XRPL");
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
