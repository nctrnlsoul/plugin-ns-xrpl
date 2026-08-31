// The plugin surface.
//
// Definition of done item 3: ZERO signing surface. There is no action, no
// service, no key handling and no transaction path anywhere in v1. The plugin
// registers one read-only provider and nothing else, and a test asserts the
// actions array is empty rather than trusting this comment.
//
// It also declares no pluginParameters. That is finding M-4's resolution made
// structural: with nothing configurable there is no operator-supplied URL to
// validate, and the scaffold's BASE_URL parameter (which shipped defaulting to
// https://api.example.com) is gone rather than guarded.

import type { Plugin } from "@elizaos/core";
import { xrplAccountProvider } from "./provider.ts";

export const xrplPlugin: Plugin = {
  name: "@northschema/plugin-xrpl",
  description:
    "Reads public XRPL ledger state for elizaOS agents. Read-only: balances and trust lines from a pinned public node, with no key material and no way to move value.",
  providers: [xrplAccountProvider],
  actions: [],
  evaluators: [],
  services: [],
};

export default xrplPlugin;
