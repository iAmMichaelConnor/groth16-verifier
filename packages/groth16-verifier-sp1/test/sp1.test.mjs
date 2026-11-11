import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  prepareFixedKey,
  prepareFixedHints,
  fixedConfigurationHash,
} from "groth16-verifier-hints/fixed";
import {
  prepareSp1Key,
  prepareSp1Hints,
  sp1PublicInputs,
  SP1_CONFIGURATION_HASH,
} from "../dist/index.js";
import { toNoirInput, FR, FQ } from "groth16-verifier-hints";
import { descriptor } from "../dist/config.js";
const f = JSON.parse(
  fs.readFileSync(new URL("./fixtures/fixed-sp1.json", import.meta.url)),
);
const started = performance.now(),
  key = prepareSp1Key(),
  keyPreparationMs = performance.now() - started;
let genuine;
test("fixed SP1 exact statement/MSM/GLV with valid alternative complete residue", async () => {
  genuine = await prepareSp1Hints({ ...f, key });
  const out = toNoirInput(genuine.producer);
  for (const name of [
    "statement",
    "application",
    "vkey",
    "public_values",
    "glv_components",
    "raw",
  ])
    assert.deepEqual(
      out[name],
      name === "public_values"
        ? f.expected[name].map(Number)
        : f.expected[name],
    );
  assert.equal(genuine.quotient.length, 152);
  assert.equal(genuine.accumulators.length, 64);
  assert.equal(genuine.capsules.private[0].values.length, 4);
  assert.equal(genuine.capsules.private[1].values.length, 2787);
  assert.equal(key.configurationHash, SP1_CONFIGURATION_HASH);
  assert.ok(Object.isFrozen(genuine.raw[0]));
});
test("configuration guard and independent alpha-beta validation reject mismatches", () => {
  assert.throws(() => prepareFixedKey(descriptor, 0n), /approved manifest/);
  const altered = structuredClone(descriptor);
  altered.tPreimage[0] = (BigInt(altered.tPreimage[0]) + 1n).toString();
  assert.throws(
    () => prepareFixedKey(altered, SP1_CONFIGURATION_HASH),
    /approved manifest/,
  );
  assert.throws(
    () => prepareFixedKey(altered, fixedConfigurationHash(altered)),
    /preimage does not match/,
  );
  const noncanonical = structuredClone(descriptor);
  noncanonical.tPreimage[0] = FQ.toString();
  assert.throws(() => fixedConfigurationHash(noncanonical), /noncanonical/);
  assert.throws(() => {
    key.configurationHash = 0n;
  }, TypeError);
});
test("SP1 rejects wrong key/bytes/program scalar and changed equation", async () => {
  await assert.rejects(
    prepareSp1Hints({ ...f, key: { ...key, configurationHash: 0n } }),
    /pinned SP1/,
  );
  await assert.rejects(
    prepareSp1Hints({ ...f, key: { ...key } }),
    /Unknown prepared fixed key/,
  );
  for (const bytes of [
    f.publicValues.slice(1),
    [256, ...f.publicValues.slice(1)],
    ["1", ...f.publicValues.slice(1)],
  ])
    assert.throws(() => sp1PublicInputs(f.vkey, bytes));
  assert.throws(() => sp1PublicInputs(FR, f.publicValues), /noncanonical/);
  const changed = Uint8Array.from(f.publicValues);
  changed[0] ^= 1;
  await assert.rejects(
    prepareSp1Hints({ ...f, key, publicValues: changed }),
    /invalid Groth16 pairing/,
  );
  const proof = structuredClone(f.proof);
  proof.pi_c = descriptor.verificationKey.vk_alpha_1;
  await assert.rejects(
    prepareSp1Hints({ ...f, key, proof }),
    /invalid Groth16 pairing/,
  );
});
test("three warm complete fixed preparations, with output equality", async () => {
  const seconds = [];
  for (let i = 0; i < 3; i++) {
    const t = performance.now();
    const result = await prepareSp1Hints({ ...f, key });
    seconds.push((performance.now() - t) / 1000);
    assert.deepEqual(result, genuine);
  }
});
test("SP1 wire parser enforces exact length/selector and explicit Fq2 reversal", async () => {
  const { parseSp1ProofBytes } = await import("../dist/index.js");
  const p = f.proof,
    words = [
      p.pi_a[0],
      p.pi_a[1],
      p.pi_b[0][1],
      p.pi_b[0][0],
      p.pi_b[1][1],
      p.pi_b[1][0],
      p.pi_c[0],
      p.pi_c[1],
    ];
  const wire =
    "0xa4594c59" +
    words.map((x) => BigInt(x).toString(16).padStart(64, "0")).join("");
  const parsed = parseSp1ProofBytes(wire);
  assert.deepEqual(parsed.pi_a, p.pi_a.slice(0, 2).map(BigInt));
  assert.deepEqual(
    parsed.pi_b,
    p.pi_b.slice(0, 2).map((a) => a.map(BigInt)),
  );
  assert.throws(() => parseSp1ProofBytes(wire + "00"), /260 bytes/);
  assert.throws(() => parseSp1ProofBytes(wire.slice(0, -2)), /260 bytes/);
  assert.throws(
    () => parseSp1ProofBytes(wire.replace("a4594c59", "00000000")),
    /selector mismatch/,
  );
  const noncanonical =
    wire.slice(0, 10) + FQ.toString(16).padStart(64, "0") + wire.slice(74);
  assert.throws(() => parseSp1ProofBytes(noncanonical), /noncanonical/);
});
test("explicit67/68 adapters use the generic fixed schemas and preserve the statement", async () => {
  const { prepareSp1Hints67, prepareSp1Hints68 } = await import(
    "../dist/index.js"
  );
  for (const [prepare, schema, accumulators, quotient] of [
    [prepareSp1Hints67, "groth16-fixed-global67-v1", 65, 108],
    [prepareSp1Hints68, "groth16-fixed-global68-v1", 66, 76],
  ]) {
    const hints = await prepare({ ...f, key });
    assert.equal(hints.schema, schema);
    assert.equal(hints.statement.toString(), f.expected.statement);
    assert.equal(hints.accumulators.length, accumulators);
    assert.equal(hints.quotient.length, quotient);
  }
});
test("hexadecimal field inputs retain the original adapter domain", async () => {
  const vkey = "0x" + BigInt(f.vkey).toString(16);
  assert.deepEqual(
    sp1PublicInputs(vkey, f.publicValues),
    sp1PublicInputs(f.vkey, f.publicValues),
  );
  const hints = await prepareSp1Hints({
    ...f,
    vkey,
    application: f.application.map((x) => "0x" + BigInt(x).toString(16)),
    key,
  });
  assert.equal(hints.statement.toString(), f.expected.statement);
});
