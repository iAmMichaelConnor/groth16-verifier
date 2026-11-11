import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  parseSp1ProofBytes,
  prepareSp1Hints,
  prepareSp1Key,
  parseSp1V6ProofBytes,
  prepareSp1V6Hints,
  prepareSp1V6Key,
  sp1V6PublicInputs,
  SP1_V6_CONFIGURATION_HASH,
  SP1_V6_VERIFIER_SELECTOR,
  SP1_V6_VK_ROOT,
} from "../dist/index.js";
import { FQ, FR } from "groth16-verifier-hints";

const fixture = (name) =>
  JSON.parse(
    fs.readFileSync(
      new URL(`../../../fixtures/sp1-v6/${name}`, import.meta.url),
    ),
  );
const bytes = (hex) => Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
const multiply = fixture("multiply.json"),
  clock = fixture("clock.json"),
  v6_0 = fixture("fibonacci-v6.0.0.json");
const v5 = JSON.parse(
  fs.readFileSync(new URL("./fixtures/fixed-sp1.json", import.meta.url)),
);
const key = prepareSp1V6Key();
const request = (f, changes = {}) => ({
  key,
  proof: f.proof,
  vkey: f.vkey,
  publicValues: bytes(f.publicValues),
  ...changes,
});
// Replace the 32-byte word at `index` (0: exit code, 1: vk root, 2: nonce, 3..10: A, B, C).
const withWord = (proof, index, value) =>
  proof.slice(0, 10 + 64 * index) +
  value.toString(16).padStart(64, "0") +
  proof.slice(74 + 64 * index);

test("selector and root are those of SP1 circuit version v6.1.0", async () => {
  const vk = fs.readFileSync(
    new URL("../../../fixtures/sp1-v6/groth16_vk.bin", import.meta.url),
  );
  const { createHash } = await import("node:crypto");
  assert.equal(
    createHash("sha256").update(vk).digest("hex").slice(0, 8),
    SP1_V6_VERIFIER_SELECTOR,
  );
  assert.equal(
    SP1_V6_VK_ROOT,
    0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352n,
  );
  assert.equal(key.configurationHash, SP1_V6_CONFIGURATION_HASH);
  assert.equal(key.inputCount, 5);
});

test("saved SP1 v6 proofs parse to the onchain verifier's public inputs", () => {
  const parsed = parseSp1V6ProofBytes(multiply.proof);
  assert.equal(parsed.exitCode, 0n);
  assert.equal(parsed.vkRoot, SP1_V6_VK_ROOT);
  assert.equal(parsed.nonce, 0n);
  assert.deepEqual(parseSp1V6ProofBytes(bytes(multiply.proof)), parsed);
  // The public inputs the producer of multiply.json recorded with it.
  assert.deepEqual(
    sp1V6PublicInputs(multiply.vkey, bytes(multiply.publicValues), parsed.nonce),
    [
      205922228921289178148469420413941188507828442907728971729484782450287372490n,
      9747890225745800339047999895000149364384159344001995441670265923588659111166n,
      0n,
      83960146348496814183195590144795274058764451818716359375255161226434597714n,
      0n,
    ],
  );
});

test("hints for both saved proofs, in sp1::v6::verify argument order", async () => {
  for (const f of [multiply, clock]) {
    const hints = await prepareSp1V6Hints(request(f));
    assert.equal(hints.schema, "groth16-fixed-global68-v1");
    assert.deepEqual(Object.keys(hints.arguments), [
      "program_vkey",
      "public_values",
      "proof_nonce",
      "raw",
      "residue",
      "components",
      "accumulators",
      "quotient",
      "block_residuals",
    ]);
    assert.equal(hints.arguments.program_vkey, BigInt(f.vkey));
    assert.deepEqual(hints.arguments.public_values, Array.from(bytes(f.publicValues)));
    assert.equal(hints.arguments.components.length, 5);
    assert.equal(hints.accumulators.length, 66);
    assert.equal(hints.quotient.length, 76);
  }
});

test("parser rejects other lengths, selectors, exit codes, roots and noncanonical words", () => {
  const p = multiply.proof;
  assert.throws(() => parseSp1V6ProofBytes(p + "00"), /356 bytes/);
  assert.throws(() => parseSp1V6ProofBytes(p.slice(0, -2)), /356 bytes/);
  assert.throws(() => parseSp1V6ProofBytes(v6_0.proof), /selector mismatch/);
  assert.throws(
    () => parseSp1V6ProofBytes("0xa4594c59" + p.slice(10)),
    /selector mismatch/,
  );
  assert.throws(() => parseSp1V6ProofBytes(withWord(p, 0, 1n)), /nonzero exit code/);
  assert.throws(
    () => parseSp1V6ProofBytes(withWord(p, 1, SP1_V6_VK_ROOT + 1n)),
    /vk root mismatch/,
  );
  assert.throws(() => parseSp1V6ProofBytes(withWord(p, 2, FR)), /nonce: noncanonical/);
  assert.throws(() => parseSp1V6ProofBytes(withWord(p, 3, FQ)), /noncanonical/);
  assert.throws(() => parseSp1V6ProofBytes(withWord(p, 4, 5n)), /A is infinity or not on the curve/);
  assert.throws(
    () => parseSp1V6ProofBytes(withWord(withWord(p, 3, 0n), 4, 0n)),
    /A is infinity/,
  );
  assert.throws(() => parseSp1V6ProofBytes(withWord(p, 7, 1n)), /B is infinity or not on the twist/);
  assert.throws(
    () => parseSp1V6ProofBytes([5, 6, 7, 8].reduce((q, i) => withWord(q, i, 0n), p)),
    /B is infinity/,
  );
  assert.throws(() => parseSp1V6ProofBytes(withWord(p, 10, 7n)), /C is infinity or not on the curve/);
});

test("tampered statements and proofs have no valid pairing", async () => {
  const values = bytes(multiply.publicValues);
  values[0] ^= 1;
  const a = parseSp1V6ProofBytes(multiply.proof).proof.pi_a;
  for (const changed of [
    request(multiply, { publicValues: values }),
    request(multiply, { vkey: clock.vkey }),
    request(multiply, { proof: withWord(multiply.proof, 2, 1n) }),
    request(multiply, { proof: withWord(multiply.proof, 4, FQ - a[1]) }),
  ])
    await assert.rejects(prepareSp1V6Hints(changed), /invalid Groth16 pairing/);
  assert.throws(() => sp1V6PublicInputs(FR, values, 0n), /noncanonical/);
  assert.throws(() => sp1V6PublicInputs(1n, values, FR), /noncanonical/);
  assert.equal(sp1V6PublicInputs(1n, [], 0n).length, 5);
});

test("v5 and v6 proofs and keys are not interchangeable", async () => {
  const v5Words = [
    v5.proof.pi_a[0],
    v5.proof.pi_a[1],
    v5.proof.pi_b[0][1],
    v5.proof.pi_b[0][0],
    v5.proof.pi_b[1][1],
    v5.proof.pi_b[1][0],
    v5.proof.pi_c[0],
    v5.proof.pi_c[1],
  ].map((x) => BigInt(x).toString(16).padStart(64, "0"));
  const v5Wire = "0xa4594c59" + v5Words.join("");
  assert.throws(() => parseSp1V6ProofBytes(v5Wire), /356 bytes/);
  // The v5 points in a v6 envelope reach the pairing check and fail it.
  const v5InV6 =
    multiply.proof.slice(0, 10 + 64 * 3) + v5Words.join("");
  await assert.rejects(
    prepareSp1V6Hints(request(multiply, { proof: v5InV6 })),
    /invalid Groth16 pairing/,
  );
  assert.throws(() => parseSp1ProofBytes(multiply.proof), /260 bytes/);
  await assert.rejects(
    prepareSp1Hints({
      ...v5,
      key: prepareSp1Key(),
      proof: parseSp1V6ProofBytes(multiply.proof).proof,
    }),
    /invalid Groth16 pairing/,
  );
  await assert.rejects(
    prepareSp1V6Hints(request(multiply, { key: prepareSp1Key() })),
    /pinned SP1 v6/,
  );
  await assert.rejects(prepareSp1Hints({ ...v5, key }), /pinned SP1/);
});
