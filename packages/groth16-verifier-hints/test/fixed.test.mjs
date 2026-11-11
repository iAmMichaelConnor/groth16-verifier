import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { bn254 } from "@noble/curves/bn254";
import {
  prepareFixedKey,
  prepareFixedHints,
  fixedConfigurationHash,
} from "../dist/fixed.js";
import { FR } from "../dist/index.js";
test("generic fixed N=1 and N=3 with genuine Circom equation and full-Fr scalar", async () => {
  const wire = JSON.parse(
    fs.readFileSync(
      new URL(
        "../../../fixtures/multiplier/verification_key.json",
        import.meta.url,
      ),
    ),
  );
  const proof = JSON.parse(
    fs.readFileSync(
      new URL("../../../fixtures/multiplier/proof.json", import.meta.url),
    ),
  );
  const a = bn254.G1.ProjectivePoint.fromAffine({
    x: BigInt(wire.vk_alpha_1[0]),
    y: BigInt(wire.vk_alpha_1[1]),
  });
  const b = bn254.G2.ProjectivePoint.fromAffine({
    x: { c0: BigInt(wire.vk_beta_2[0][0]), c1: BigInt(wire.vk_beta_2[0][1]) },
    y: { c0: BigInt(wire.vk_beta_2[1][0]), c1: BigInt(wire.vk_beta_2[1][1]) },
  });
  const flatten = (v) =>
    typeof v === "bigint" ? [v.toString()] : Object.values(v).flatMap(flatten);
  const d = {
    schema: "groth16-fixed-global66-v1",
    verificationKey: wire,
    tPreimage: flatten(bn254.pairing(a.negate(), b, false)),
  };
  const p = prepareFixedKey(d, fixedConfigurationHash(d));
  const one = await prepareFixedHints({ key: p, proof, publicInputs: ["33"] });
  assert.equal(one.quotient.length, 152);
  const d3 = structuredClone(d);
  d3.verificationKey.nPublic = 3;
  d3.verificationKey.IC.push([...wire.IC[1]], ["0", "1", "0"]);
  const p3 = prepareFixedKey(d3, fixedConfigurationHash(d3));
  const three = await prepareFixedHints({
    key: p3,
    proof,
    publicInputs: ["16", "17", FR - 1n],
  });
  assert.deepEqual(three.raw, one.raw);
  assert.equal(three.glvComponents.length, 3);
  await assert.rejects(
    prepareFixedHints({ key: p3, proof, publicInputs: ["33"] }),
    /expected 3/,
  );
});
test("transcript primitive rejects coercion and noncanonical fields", async () => {
  const { poseidon2Hash } = await import("../dist/transcript.js");
  assert.equal(poseidon2Hash(["0x01", 2n]), poseidon2Hash([1n, "2"]));
  for (const input of [[1], [-1n], [FR], ["01"], null])
    assert.throws(() => poseidon2Hash(input));
});
