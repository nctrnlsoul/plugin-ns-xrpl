// Kickoff step 9: prove the real path early.
//
// "Compiling and importing cleanly is not evidence that it works." This drives
// the actual provider against the actual pinned public node over the actual
// network, and prints what came back so a human can look at it.
//
// Not part of `verify`: it needs the network, and a gate that fails when the
// wifi drops teaches people to skip the gate. Run it deliberately.
//
//   node scripts/live-check.mjs

import { createXrplProvider } from "../src/provider.ts";
import { XRPL_NODE_URL } from "../src/core/node-url.ts";

const CASES = [
  ["funded account", "what is the balance of rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"],
  ["issuer with many trust lines", "check rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B"],
  // D6. One message, two addresses, one lookup. The count itself is computed
  // from the message and needs no network, so what this case adds over the unit
  // tests is the thing only the real path shows: the notice standing in a real
  // report, beside real ledger data, inside the real size cap. Both addresses
  // are the known-good ones above, so a failure here is about the notice rather
  // than about either account.
  [
    "two addresses, only the first looked up",
    "compare rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh with rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",
  ],
  ["bad checksum", "look up rp4rt3JQKZaC7Docd1kUswQpQBGiRJs6Fk"],
  ["no address at all", "what is the weather today"],
];

const provider = createXrplProvider();
console.log(`node: ${XRPL_NODE_URL}`);
console.log(`provider: ${provider.name}\n`);

let failures = 0;
for (const [label, text] of CASES) {
  const started = Date.now();
  let result;
  try {
    result = await provider.get({}, { content: { text } }, undefined);
  } catch (err) {
    console.log(`[${label}] THREW, which must never happen: ${err?.message}`);
    failures++;
    continue;
  }
  const ms = Date.now() - started;
  const body = result?.text ?? "";
  console.log(`${"=".repeat(72)}`);
  console.log(`[${label}]  ${ms}ms  ${body.length} chars`);
  console.log(`${"=".repeat(72)}`);
  console.log(body === "" ? "(silent: no address in the message, nothing attempted)" : body);
  console.log();
}

console.log(failures === 0 ? "LIVE CHECK: nothing threw." : `LIVE CHECK: ${failures} threw.`);
process.exit(failures === 0 ? 0 : 1);
