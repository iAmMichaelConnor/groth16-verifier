// Deterministic real ABI witnesses for the maintained global68 producer.
// The injected kernel passes host preflight; the complete Noir relation must reject it.
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { createVerifier } from "../dist/current.js";
import { prepareRuntimeKey, toNoirInput } from "../dist/index.js";
import { RUNTIME_68 } from "../dist/schemas.js";
const directory = process.argv[2] || process.env.GROTH16_HINT_EVIDENCE_DIR;
if (!directory)
  throw new Error("Pass an output directory or set GROTH16_HINT_EVIDENCE_DIR");
const read = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url)));
const key = read("../../../fixtures/multiplier/verification_key.json");
const profile = read("./fixtures/profiles/offchain-runtime.json");
profile.keyHash = prepareRuntimeKey(key).keyHash.toString();
const verifier = createVerifier(profile, key);
const request = {
  proof: read("../../../fixtures/multiplier/proof.json"),
  publicInputs: ["33"],
  application: ["1", "1", "7", "11", "13", "17"],
};
const honest = await verifier.prepare(request);
const forged = new Uint8Array(RUNTIME_68.outputBytes);
// c=c_inverse=w=1. Zero quotient/residuals pass the aggregate host check,
// but zero intermediate accumulators violate the authenticated Miller relation.
for (const index of [12, 24, 36]) forged[index * 32 + 31] = 1;
const malicious = await verifier.prepare(request, { kernel: () => forged });
assert.equal(malicious.statement, honest.statement);
assert.notDeepEqual(malicious.producerInputs, honest.producerInputs);
fs.mkdirSync(directory, { recursive: true });
fs.writeFileSync(
  path.join(directory, "profile.json"),
  JSON.stringify(profile),
  { flag: "wx" },
);
for (const [name, packet] of [
  ["producer-input", honest],
  ["forged-kernel-input", malicious],
]) {
  const v = toNoirInput(packet.producerInputs);
  const top = Object.entries(v)
    .filter(([key]) => key !== "key")
    .map(([key, value]) => `${key} = ${JSON.stringify(value)}`)
    .join("\n");
  const key = Object.entries(v.key)
    .map(([key, value]) => `${key} = ${JSON.stringify(value)}`)
    .join("\n");
  fs.writeFileSync(
    path.join(directory, `${name}.toml`),
    top + "\n\n[key]\n" + key + "\n",
    { flag: "wx" },
  );
}
