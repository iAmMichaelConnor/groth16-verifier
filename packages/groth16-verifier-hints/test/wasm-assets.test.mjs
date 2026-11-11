import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { bn254 } from "@noble/curves/bn254";
import { createProfileWasmKernel, HINTS_WASM_V1 } from "../dist/wasm-assets.js";
import { createVerifier } from "../dist/current.js";
import { prepareRuntimeKey } from "../dist/index.js";
import { fixedConfigurationHash } from "../dist/fixed.js";
import * as schemas from "../dist/schemas.js";

const read = (path) =>
  JSON.parse(fs.readFileSync(new URL(path, import.meta.url)));
const bytes = fs.readFileSync(
  new URL(
    "../../groth16-verifier-hints-wasm/v1/hints-kernel.wasm",
    import.meta.url,
  ),
);
const manifest = read("../../groth16-verifier-hints-wasm/v1/manifest.json");
const vk = read("../../../fixtures/multiplier/verification_key.json");
const proof = read("../../../fixtures/multiplier/proof.json");
const profile = read("./fixtures/profiles/private-runtime.json");
profile.keyHash = prepareRuntimeKey(vk).keyHash.toString();
const request = {
  proof,
  publicInputs: ["33"],
  application: [1n, 1n, 7n, 11n, 13n, 17n],
};

test("asset manifest binds all schema metadata; wrong bytes/profile rejected before use", async () => {
  assert.equal(manifest.sha256, HINTS_WASM_V1.sha256);
  assert.equal(manifest.bytes, bytes.length);
  const plain = (value) =>
    JSON.parse(
      JSON.stringify(value, (_key, v) =>
        typeof v === "bigint" ? v.toString() : v,
      ),
    );
  assert.deepEqual(
    manifest.schemas,
    Object.values(schemas)
      .sort((a, b) => a.id - b.id)
      .map(plain),
  );
  const module = await WebAssembly.compile(bytes);
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  await assert.rejects(
    createProfileWasmKernel(profile, bytes.subarray(1)),
    /length/,
  );
  const altered = Uint8Array.from(bytes);
  altered[100] ^= 1;
  await assert.rejects(createProfileWasmKernel(profile, altered), /SHA256/);
  await assert.rejects(
    createProfileWasmKernel(
      { ...profile, certificate: "groth16-runtime-global66-v1" },
      bytes,
    ),
    /mismatch/,
  );
});

test("profile-selected WASM reproduces complete current runtime and generic fixed packets", async () => {
  const runtime = createVerifier(profile, vk);
  assert.deepEqual(
    await runtime.prepare(request, {
      kernel: await createProfileWasmKernel(profile, bytes),
    }),
    await runtime.prepare(request),
  );
  const a = bn254.G1.ProjectivePoint.fromAffine({
    x: BigInt(vk.vk_alpha_1[0]),
    y: BigInt(vk.vk_alpha_1[1]),
  });
  const b = bn254.G2.ProjectivePoint.fromAffine({
    x: { c0: BigInt(vk.vk_beta_2[0][0]), c1: BigInt(vk.vk_beta_2[0][1]) },
    y: { c0: BigInt(vk.vk_beta_2[1][0]), c1: BigInt(vk.vk_beta_2[1][1]) },
  });
  const flatten = (value) =>
    typeof value === "bigint"
      ? [value.toString()]
      : Object.values(value).flatMap(flatten);
  const descriptor = {
    schema: "groth16-fixed-key-v1",
    verificationKey: vk,
    tPreimage: flatten(bn254.pairing(a.negate(), b, false)),
  };
  const fixedProfile = {
    ...profile,
    keyPolicy: "fixed",
    certificate: "groth16-fixed-global68-v1",
    configurationHash: fixedConfigurationHash({
      ...descriptor,
      schema: "groth16-fixed-global66-v1",
    }).toString(),
  };
  const fixed = createVerifier(fixedProfile, descriptor);
  assert.deepEqual(
    await fixed.prepare(request, {
      kernel: await createProfileWasmKernel(fixedProfile, bytes),
    }),
    await fixed.prepare(request),
  );
});
