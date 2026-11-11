// Versioned WASM factories (global66, global67, global68) against the built
// v1 asset of packages/groth16-verifier-hints-wasm. The asset is not stored in the source tree:
// build it as described in the groth16-verifier-hints README (Optional WASM kernel). Every expectation here compares the
// WASM kernel with the TypeScript/Noble preparation of the same repository fixtures.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  createWasmKernels,
  createWasmKernels67,
  createWasmKernels68,
  createRuntimeWasmKernels68,
} from "../dist/wasm.js";
import {
  prepareFixedKey,
  fixedConfigurationHash,
  prepareFixedHints,
  prepareFixedHints67,
  prepareFixedHints68,
} from "../dist/fixed.js";
import {
  prepareRuntimeKey,
  prepareRuntimeHints,
  prepareRuntimeHints67,
  prepareRuntimeHints68,
} from "../dist/index.js";

const read = (path) =>
  JSON.parse(fs.readFileSync(new URL(path, import.meta.url)));
const bytes = fs.readFileSync(
  new URL(
    "../../groth16-verifier-hints-wasm/v1/hints-kernel.wasm",
    import.meta.url,
  ),
);
const wire = read("../../../fixtures/multiplier/verification_key.json");
const { bn254 } = await import("@noble/curves/bn254");
const alpha = bn254.G1.ProjectivePoint.fromAffine({
  x: BigInt(wire.vk_alpha_1[0]),
  y: BigInt(wire.vk_alpha_1[1]),
});
const beta = bn254.G2.ProjectivePoint.fromAffine({
  x: { c0: BigInt(wire.vk_beta_2[0][0]), c1: BigInt(wire.vk_beta_2[0][1]) },
  y: { c0: BigInt(wire.vk_beta_2[1][0]), c1: BigInt(wire.vk_beta_2[1][1]) },
});
const flatten = (value) =>
  typeof value === "bigint"
    ? [value.toString()]
    : Object.values(value).flatMap(flatten);
const descriptor = {
  schema: "groth16-fixed-global66-v1",
  verificationKey: wire,
  tPreimage: flatten(bn254.pairing(alpha.negate(), beta, false)),
};
const fixed = {
  key: prepareFixedKey(descriptor, fixedConfigurationHash(descriptor)),
  proof: read("../../../fixtures/multiplier/proof.json"),
  publicInputs: [33n],
};
const runtime = {
  key: prepareRuntimeKey(
    read("../../../fixtures/multiplier/verification_key.json"),
  ),
  proof: read("../../../fixtures/multiplier/proof.json"),
  publicInputs: [33n],
  application: [1n, 1n, 7n, 11n, 13n, 17n],
};

// A module with the versioned exports and a chosen capability mask but no arithmetic.
function stubModule(mask) {
  const vec = (items) => [items.length, ...items.flat()];
  const section = (id, content) => [id, content.length, ...content];
  const name = (text) => [text.length, ...Buffer.from(text)];
  const body = (...code) => [code.length + 2, 0, ...code, 0x0b];
  const exports = [
    ["abi_version", 0, 0],
    ["prepare_kernel", 0, 1],
    ["run_kernel", 0, 2],
    ["input_ptr", 0, 3],
    ["output_ptr", 0, 4],
    ["schema_mask", 0, 5],
    ["memory", 2, 0],
  ];
  return Uint8Array.from([
    0,
    0x61,
    0x73,
    0x6d,
    1,
    0,
    0,
    0,
    ...section(1, [3, 0x60, 0, 1, 0x7f, 0x60, 0, 0, 0x60, 1, 0x7f, 1, 0x7f]),
    ...section(3, [6, 0, 1, 2, 0, 0, 0]),
    ...section(5, [1, 0, 1]),
    ...section(
      7,
      vec(exports.map(([n, kind, index]) => [...name(n), kind, index])),
    ),
    ...section(
      10,
      vec([
        body(0x41, 1),
        body(),
        body(0x41, 0),
        body(0x41, 0),
        body(0x41, 0),
        body(0x41, mask),
      ]),
    ),
  ]);
}

test("factories require the schema capabilities they expose", async () => {
  await assert.rejects(() => createWasmKernels67(stubModule(7)), /global67/);
  await assert.rejects(() => createWasmKernels68(stubModule(15)), /global68/);
  await assert.rejects(
    () => createRuntimeWasmKernels68(stubModule(31)),
    /global68/,
  );
  await createRuntimeWasmKernels68(stubModule(63));
  await assert.rejects(
    () => createWasmKernels(Uint8Array.of(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0)),
    /Missing WASM export/,
  );
  assert.equal((await createWasmKernels68(bytes)).runtime68, undefined);
});

test("global66 WASM equals Noble; adapter checks length and a trap poisons the instance", async () => {
  const kernels = await createWasmKernels(bytes);
  assert.deepEqual(
    await prepareRuntimeHints(runtime, { kernel: kernels.runtime }),
    await prepareRuntimeHints(runtime),
  );
  assert.deepEqual(
    await prepareFixedHints(fixed, { kernel: kernels.fixed }),
    await prepareFixedHints(fixed),
  );
  assert.throws(() => kernels.fixed(new Uint8Array(959)), /960-byte/);
  const invalid = new Uint8Array(960).fill(255, 0, 32);
  assert.throws(() => kernels.fixed(invalid), WebAssembly.RuntimeError);
  assert.throws(() => kernels.runtime(new Uint8Array(864)), /recreate/);
});

// [name, request, api, expected shape, [wrong callback, expected error]...]
const cases = [
  [
    "fixed67",
    fixed,
    prepareFixedHints67,
    {
      schema: "groth16-fixed-global67-v1",
      accumulators: 65,
      quotient: 108,
      fields: 2691,
      slot: 0x47524f544831365f5052454649585f5631n,
    },
    ["fixed", /response must/],
    ["fixed68", /30304/],
  ],
  [
    "runtime67",
    runtime,
    prepareRuntimeHints67,
    {
      schema: "groth16-runtime-global67-v1",
      accumulators: 65,
      quotient: 115,
      fields: 2820,
      slot: 0x4731365f52554e54494d455f50524546495800n,
    },
    ["runtime", /response must/],
    ["runtime68", /30528/],
  ],
  [
    "fixed68",
    fixed,
    prepareFixedHints68,
    {
      schema: "groth16-fixed-global68-v1",
      accumulators: 66,
      quotient: 76,
      fields: 2631,
      slot: 0x47524f544831365f5052454649585f5441494c5f5631n,
    },
    ["fixed67", /29664/],
  ],
  [
    "runtime68",
    runtime,
    prepareRuntimeHints68,
    {
      schema: "groth16-runtime-global68-v1",
      accumulators: 66,
      quotient: 94,
      fields: 2793,
      slot: 0x4731365f52554e54494d455f5441494c00n,
    },
    ["runtime67", /30240/],
  ],
];
for (const [name, request, api, shape, ...wrong] of cases)
  test(`${name} WASM equals Noble with exact tags and refuses another schema's callback`, async () => {
    const kernels = await createRuntimeWasmKernels68(bytes);
    const hints = await api(request, { kernel: kernels[name] });
    assert.deepEqual(hints, await api(request));
    assert.equal(hints.schema, shape.schema);
    const pairing = hints.pairing ?? hints;
    assert.equal(pairing.accumulators.length, shape.accumulators);
    assert.equal(pairing.quotient.length, shape.quotient);
    assert.equal(hints.capsules.private[0].slot, shape.slot);
    assert.equal(hints.capsules.private[1].values.length, shape.fields);
    for (const [other, message] of wrong)
      await assert.rejects(
        () => api(request, { kernel: kernels[other] }),
        message,
      );
  });

test("invalid equations trap in the 67 and 68 kernels", async () => {
  const changed = [34n];
  for (const [backend, request, api] of [
    ["fixed67", { ...fixed, publicInputs: changed }, prepareFixedHints67],
    ["fixed68", { ...fixed, publicInputs: changed }, prepareFixedHints68],
    ["runtime67", { ...runtime, publicInputs: [34n] }, prepareRuntimeHints67],
    ["runtime68", { ...runtime, publicInputs: [34n] }, prepareRuntimeHints68],
  ]) {
    const kernels = await createRuntimeWasmKernels68(bytes);
    await assert.rejects(
      () => api(request, { kernel: kernels[backend] }),
      WebAssembly.RuntimeError,
    );
    assert.throws(() => kernels.fixed(new Uint8Array(960)), /recreate/);
  }
});
