import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { bn254 } from "@noble/curves/bn254";
import {
  parseProfile,
  profileHash,
  statementId,
  createVerifier,
  assertPreparedRequest,
} from "../dist/current.js";
import {
  prepareRuntimeKey,
  parseVerificationKey,
  FR,
  FQ,
} from "../dist/index.js";
import { fixedConfigurationHash } from "../dist/fixed.js";
const read = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url)));
const vk = read("../../../fixtures/multiplier/verification_key.json");
const proof = read("../../../fixtures/multiplier/proof.json");
const profile = read("./fixtures/profiles/private-runtime.json");
profile.keyHash = prepareRuntimeKey(vk).keyHash.toString();
const request = {
  proof,
  publicInputs: ["33"],
  application: ["1", "1", "7", "11", "13", "17"],
};
let runtime;
test("current profile rejects incompatible schemas, keys, arities and backend declarations before hints", async () => {
  const parsed = parseProfile(profile);
  assert.ok(Object.isFrozen(parsed.toolchain));
  assert.equal(
    profileHash(parsed),
    profileHash(Object.fromEntries(Object.entries(profile).reverse())),
  );
  for (const delta of [
    { extra: true },
    { keyHash: "00" },
    { keyHash: FR.toString() },
    { configurationHash: "0" },
    { inputCount: 257 },
    { inputCount: -1 },
    { certificate: "groth16-runtime-global66-v1" },
    { mode: "public" },
    { keyPolicy: "unknown" },
    { toolchain: { ...profile.toolchain, noirCommit: "untrusted" } },
    { schema: "groth16-verifier-profile-v1" },
    // Profiles must name the Aztec v6.0.0 release.
    {
      toolchain: {
        ...profile.toolchain,
        aztecCommit: "9a642fcbf0045c5445ae9dfd6f5f1c21e5a0bd3f",
      },
    },
    // stock-v6 is the only backend.
    { toolchain: { ...profile.toolchain, backend: "other-v6" } },
  ])
    assert.throws(() => parseProfile({ ...profile, ...delta }));
  assert.throws(
    () => createVerifier({ ...profile, keyHash: "0" }, vk),
    /authorization/,
  );
  assert.throws(
    () => createVerifier({ ...profile, inputCount: 2 }, vk),
    /input count/,
  );
  assert.throws(
    () =>
      parseProfile({
        ...profile,
        toolchain: { ...profile.toolchain, backend: "other-v6" },
      }),
    /Incompatible backend declaration/,
  );
  assert.throws(
    () => createVerifier(profile, vk, { backend: "other-v6" }),
    /Backend\/profile mismatch/,
  );
  assert.equal(
    createVerifier(profile, vk, { backend: "stock-v6" }).profile.mode,
    "private",
  );
  const v = createVerifier(profile, vk);
  let called = false;
  await assert.rejects(
    () =>
      v.prepare(
        { ...request, publicInputs: [] },
        {
          kernel: () => {
            called = true;
            throw Error("kernel");
          },
        },
      ),
    /expected 1/,
  );
  assert.equal(called, false);
});
test("runtime current packet binds key, statement, selected capsules and producer data", async () => {
  runtime = await createVerifier(profile, vk).prepare(request);
  assert.equal(runtime.hints.schema, "groth16-runtime-global68-v1");
  assert.equal(runtime.statement, runtime.hints.statement);
  assert.equal(
    runtime.statement,
    statementId(profile, request.application, request.publicInputs),
  );
  assert.notEqual(
    runtime.statement,
    statementId(
      profile,
      ["1", "1", "7", "11", "13", "18"],
      request.publicInputs,
    ),
  );
  assert.deepEqual(runtime.capsules, runtime.hints.capsules.private);
  assert.equal(runtime.producerInputs.statement, runtime.statement);
  assertPreparedRequest(profile, runtime);
  assert.throws(
    () => assertPreparedRequest({ ...profile, name: "another" }, runtime),
    /mismatch/,
  );
  assert.throws(
    () => assertPreparedRequest(profile, { ...runtime }),
    /mismatch/,
  );
  assert.throws(() => {
    runtime.callArguments.application[0] = 2n;
  }, TypeError);
});
test("fixed current descriptor and generic producer have the same statement as runtime", async () => {
  const a = bn254.G1.ProjectivePoint.fromAffine({
    x: BigInt(vk.vk_alpha_1[0]),
    y: BigInt(vk.vk_alpha_1[1]),
  });
  const b = bn254.G2.ProjectivePoint.fromAffine({
    x: { c0: BigInt(vk.vk_beta_2[0][0]), c1: BigInt(vk.vk_beta_2[0][1]) },
    y: { c0: BigInt(vk.vk_beta_2[1][0]), c1: BigInt(vk.vk_beta_2[1][1]) },
  });
  const flatten = (v) =>
    typeof v === "bigint" ? [v.toString()] : Object.values(v).flatMap(flatten);
  const descriptor = {
    schema: "groth16-fixed-key-v1",
    verificationKey: vk,
    tPreimage: flatten(bn254.pairing(a.negate(), b, false)),
  };
  const p = {
    ...profile,
    keyPolicy: "fixed",
    mode: "offchain",
    certificate: "groth16-fixed-global68-v1",
    configurationHash: fixedConfigurationHash({
      ...descriptor,
      schema: "groth16-fixed-global66-v1",
    }).toString(),
  };
  assert.throws(
    () =>
      createVerifier(p, { ...descriptor, schema: "groth16-fixed-global66-v1" }),
    /descriptor schema/,
  );
  const result = await createVerifier(p, descriptor).prepare(request);
  assert.equal(result.statement, runtime.statement);
  assert.equal(result.hints.quotient.length, 76);
  assert.deepEqual(result.capsules, []);
  assert.equal(result.producerInputs.glv_components.length, 1);
  assert.equal(result.producerInputs.statement, result.statement);
  const direct = await createVerifier(
    { ...p, mode: "private" },
    descriptor,
  ).prepare(request);
  assert.equal(direct.capsules[1].values.length, 2739);
  assert.deepEqual(
    direct.capsules[1].values.slice(0, 108),
    direct.hints.residue.flat(),
  );
  assert.deepEqual(
    direct.capsules[1].values.slice(108),
    direct.hints.capsules.private[1].values,
  );
  assert.equal(direct.hints.capsules.private[1].values.length, 2631);
  await assert.rejects(
    () =>
      createVerifier(p, descriptor).prepare({
        ...request,
        publicInputs: ["34"],
      }),
    /invalid Groth16 pairing/,
  );
});
test("N=0 keeps the same valid pairing while omitting forbidden empty ABI inputs", async () => {
  // Fold the known public-input contribution into IC[0]. This changes the key,
  // not the pairing equation; it tests the zero-arity interface without proving.
  const point = (p) =>
    bn254.G1.ProjectivePoint.fromAffine({ x: BigInt(p[0]), y: BigInt(p[1]) });
  const l = point(vk.IC[0]).add(point(vk.IC[1]).multiply(33n)).toAffine();
  const wire = {
    ...structuredClone(vk),
    nPublic: 0,
    IC: [[l.x.toString(), l.y.toString(), "1"]],
  };
  const p = {
    ...profile,
    inputCount: 0,
    keyHash: prepareRuntimeKey(wire).keyHash.toString(),
  };
  const packet = await createVerifier(p, wire).prepare({
    ...request,
    publicInputs: [],
  });
  assert.deepEqual(packet.publicInputs, []);
  assert.equal("public_inputs" in packet.callArguments, false);
  for (const name of ["inputs", "magnitudes", "negative"])
    assert.equal(name in packet.producerInputs, false);
  assert.deepEqual(packet.hints.claimedL, runtime.hints.claimedL);
  const a = point(wire.vk_alpha_1);
  const b = bn254.G2.ProjectivePoint.fromAffine({
    x: { c0: BigInt(wire.vk_beta_2[0][0]), c1: BigInt(wire.vk_beta_2[0][1]) },
    y: { c0: BigInt(wire.vk_beta_2[1][0]), c1: BigInt(wire.vk_beta_2[1][1]) },
  });
  const flatten = (v) =>
    typeof v === "bigint" ? [v.toString()] : Object.values(v).flatMap(flatten);
  const descriptor = {
    schema: "groth16-fixed-key-v1",
    verificationKey: wire,
    tPreimage: flatten(bn254.pairing(a.negate(), b, false)),
  };
  const fp = {
    ...p,
    keyPolicy: "fixed",
    certificate: "groth16-fixed-global68-v1",
    configurationHash: fixedConfigurationHash({
      ...descriptor,
      schema: "groth16-fixed-global66-v1",
    }).toString(),
  };
  const fixed = await createVerifier(fp, descriptor).prepare({
    ...request,
    publicInputs: [],
  });
  assert.equal(fixed.capsules.length, 1);
  assert.equal(fixed.capsules[0].values.length, 2739);
  assert.equal("inputs" in fixed.producerInputs, false);
  assert.equal("glv_components" in fixed.producerInputs, false);
});

// Degenerate keys pass every per-point check but must be rejected.
test("key parser rejects delta = +-gamma, delta = generator and all-infinity IC", () => {
  const copy = () => JSON.parse(JSON.stringify(vk));
  const neg = (p) => [
    p[0],
    p[1].map((y) => ((FQ - BigInt(y)) % FQ).toString()),
    p[2],
  ];
  const generator = [
    [
      bn254.G2.ProjectivePoint.BASE.toAffine().x.c0,
      bn254.G2.ProjectivePoint.BASE.toAffine().x.c1,
    ],
    [
      bn254.G2.ProjectivePoint.BASE.toAffine().y.c0,
      bn254.G2.ProjectivePoint.BASE.toAffine().y.c1,
    ],
    [1n, 0n],
  ].map((c) => c.map(String));
  // The fixture is a snarkjs key: gamma is the generator, delta is contributed.
  assert.deepEqual(vk.vk_gamma_2, generator);
  const cases = [];
  let key = copy();
  key.vk_delta_2 = key.vk_gamma_2;
  cases.push([key, /plus or minus gamma/]);
  key = copy();
  key.vk_delta_2 = neg(key.vk_gamma_2);
  cases.push([key, /plus or minus gamma/]);
  key = copy();
  key.vk_gamma_2 = key.vk_beta_2; // gamma is no longer the generator
  key.vk_delta_2 = generator;
  cases.push([key, /G2 generator/]);
  key = copy();
  key.vk_gamma_2 = key.vk_beta_2;
  key.vk_delta_2 = neg(generator);
  cases.push([key, /G2 generator/]);
  key = copy();
  key.IC = key.IC.map(() => ["0", "1", "0"]);
  cases.push([key, /every IC point is infinity/]);
  key = copy();
  key.nPublic = 0;
  key.IC = [["0", "0"]];
  cases.push([key, /every IC point is infinity/]);
  for (const [bad, message] of cases) {
    assert.throws(() => parseVerificationKey(bad), message);
    assert.throws(() => prepareRuntimeKey(bad), message);
  }
  // Valid exceptional keys stay accepted: one infinity IC entry, and gamma = generator.
  key = copy();
  key.IC[0] = ["0", "1", "0"];
  assert.equal(prepareRuntimeKey(key).inputCount, 1);
  key = copy();
  key.vk_delta_2 = neg(key.vk_delta_2);
  assert.equal(prepareRuntimeKey(key).inputCount, 1);
});
