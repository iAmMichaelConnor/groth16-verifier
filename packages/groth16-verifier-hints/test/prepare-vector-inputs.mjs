// Host hints of one saved proof, as the JSON Noir ABI inputs of the matching producer.
// Usage: node prepare-vector-inputs.mjs <profile.json> <key.json> <proof.json> <public input>...
// `profile.json` and `key.json` come from `python3 -m groth16.generate`. Hint
// preparation only: no setup, proof or backend is involved.
import fs from "node:fs";
import { createVerifier } from "../dist/current.js";
import { toNoirInput } from "../dist/index.js";

const [profileFile, keyFile, proofFile, ...publicInputs] =
  process.argv.slice(2);
if (!profileFile || !keyFile || !proofFile)
  throw new Error(
    "Usage: prepare-vector-inputs.mjs <profile> <key> <proof> <input>...",
  );
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const verifier = createVerifier(read(profileFile), read(keyFile));
const packet = await verifier.prepare({
  proof: read(proofFile),
  publicInputs,
  application: ["1", "1", "7", "11", "13", "17"],
});
process.stdout.write(JSON.stringify(toNoirInput(packet.producerInputs)) + "\n");
