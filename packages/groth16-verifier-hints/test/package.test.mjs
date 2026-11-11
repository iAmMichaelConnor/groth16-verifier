import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as api from "../dist/index.js";
import { bn254 } from "@noble/curves/bn254";
const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const read = (p) => JSON.parse(fs.readFileSync(path.join(root, p), "utf8"));
const key = read("fixtures/multiplier/verification_key.json");
const proof = read("fixtures/multiplier/proof.json");
const expected = read(
  "packages/groth16-verifier-hints/test/fixtures/producer.json",
).data;
const application = ["1", "1", "7", "11", "13", "17"];
const handle = api.prepareRuntimeKey(key);
const request = (prepared = handle) => ({
  key: prepared,
  proof,
  publicInputs: ["33"],
  application,
});
let baseline;
test("complete producer inputs and capsules equal independent Python/Noir fixture", async () => {
  baseline = await api.prepareRuntimeHints(request());
  assert.deepEqual(api.toNoirInput(baseline.producer), expected);
  assert.deepEqual(
    baseline.capsules.private.map((c) => c.values.length),
    [10, 3003],
  );
  assert.equal(baseline.flatKey.length, 18);
  assert.equal(api.privateCallArguments(baseline, 1).public_inputs[0], 33n);
  assert.throws(() => api.privateCallArguments(baseline, 2), /count mismatch/);
});
test("prepared key and returned values cannot be mutated or forged", async () => {
  assert.throws(() => {
    handle.keyHash = 0n;
  }, TypeError);
  await assert.rejects(
    api.prepareRuntimeHints(request({ ...handle })),
    /Unknown prepared key/,
  );
  assert.throws(() => {
    baseline.key.ic[0][0][0] = 0n;
  }, TypeError);
  assert.throws(() => {
    baseline.capsules.private[0].values[0] = 0n;
  }, TypeError);
  const copy = structuredClone(key),
    prepared = api.prepareRuntimeKey(copy);
  copy.IC[0][0] = "0";
  assert.equal(prepared.keyHash, handle.keyHash);
});
test("strict integer and shape parser rejects aliases and coercions", () => {
  for (const bad of [
    1,
    Number.MAX_SAFE_INTEGER + 1,
    -1n,
    "-1",
    "+1",
    "01",
    " 1",
    "1.0",
    "1e0",
    "",
    true,
    null,
    api.FQ.toString(),
  ]) {
    const p = structuredClone(proof);
    p.pi_a[0] = bad;
    assert.throws(() => api.parseProof(p));
  }
  for (const field of ["protocol", "curve"]) {
    const p = structuredClone(proof);
    p[field] = "other";
    assert.throws(() => api.parseProof(p));
  }
  assert.throws(
    () => api.parseProof({ ...proof, ignored: 1 }),
    /unknown property/,
  );
  assert.throws(
    () => api.prepareRuntimeKey({ ...key, nPublic: "1" }),
    /nPublic/,
  );
  assert.throws(() => api.prepareRuntimeKey({ ...key, IC: [] }), /IC/);
  const p = structuredClone(proof);
  p.pi_b[2] = ["0", "0"];
  assert.throws(() => api.parseProof(p), /affine/);
});
test("strict canonical scalar, context and arity reject before kernel use", async () => {
  for (const inputs of [[], ["33", "0"], [33], ["-1"], [api.FR.toString()]])
    await assert.rejects(
      api.prepareRuntimeHints({ ...request(), publicInputs: inputs }),
    );
  await assert.rejects(
    api.prepareRuntimeHints({
      ...request(),
      application: application.slice(1),
    }),
  );
  await assert.rejects(
    api.prepareRuntimeHints({
      ...request(),
      application: [...application.slice(0, 5), api.FR.toString()],
    }),
  );
});
test("changed public input and changed valid G1 proof reject pairing", async () => {
  await assert.rejects(
    api.prepareRuntimeHints({ ...request(), publicInputs: ["34"] }),
    /invalid Groth16 pairing/,
  );
  const p = structuredClone(proof);
  p.pi_c = key.vk_alpha_1;
  await assert.rejects(
    api.prepareRuntimeHints({ ...request(), proof: p }),
    /invalid Groth16 pairing/,
  );
});
test("off-curve and genuine on-curve off-subgroup G2 reject", async () => {
  const p = structuredClone(proof);
  p.pi_a = ["1", "1", "1"];
  await assert.rejects(api.prepareRuntimeHints({ ...request(), proof: p }));
  // Deterministic: the smallest x = (i, 1) whose twist equation has a root and whose
  // point is not in the order-r subgroup. Most twist points are not (cofactor is large).
  const F2 = bn254.fields.Fp2;
  let q;
  for (let i = 2n; !q; i++) {
    const x = { c0: i, c1: 1n };
    const rhs = F2.add(F2.mul(F2.sqr(x), x), bn254.G2.CURVE.b);
    let y;
    try {
      y = F2.sqrt(rhs);
    } catch {
      continue; // no square root: x is not on the twist
    }
    if (bn254.G2.ProjectivePoint.fromAffine({ x, y }).isTorsionFree()) continue;
    q = structuredClone(proof);
    q.pi_b = [
      [x.c0, x.c1],
      [y.c0, y.c1],
      [1n, 0n],
    ];
  }
  await assert.rejects(
    api.prepareRuntimeHints({ ...request(), proof: q }),
    /subgroup/,
  );
});
test("GLV recomposes zero, full Fr boundary and deterministic wide scalars", () => {
  const lambda =
    21888242871839275217838484774961031246154997185409878258781734729429964517155n;
  let state = 1n;
  const values = [0n, 1n, api.FR - 1n, api.FR / 2n];
  for (let i = 0; i < 32; i++) {
    state = (state * 6364136223846793005n + 1442695040888963407n) % api.FR;
    values.push(state);
  }
  for (const x of values) {
    const d = api.decomposeScalar(x);
    assert.ok(d.magnitudes.every((m) => m < 1n << 126n));
    const [a, b] = d.magnitudes.map((m, i) => (d.negative[i] ? -m : m));
    assert.equal((((a + lambda * b - x) % api.FR) + api.FR) % api.FR, 0n);
  }
  assert.deepEqual(api.decomposeScalar(0n).negative, [false, false]);
});
test("N=2 and N=3 honest generic keys, infinity IC and full-width scalar supported", async () => {
  for (const n of [2, 3]) {
    const extended = structuredClone(key);
    extended.nPublic = n;
    for (let i = 1; i < n; i++) extended.IC.push(["0", "1", "0"]);
    const h = await api.prepareRuntimeHints({
      key: api.prepareRuntimeKey(extended),
      proof,
      publicInputs: ["33", ...Array(n - 1).fill((api.FR - 1n).toString())],
      application,
    });
    assert.equal(h.inputCount, n);
    assert.equal(h.flatKey.length, 16 + 2 * n);
    assert.equal(h.magnitudes.length, n);
    assert.deepEqual(h.claimedL, baseline.claimedL);
    assert.equal(h.capsules.private[0].values.length, 6 + 4 * n);
  }
});
test("generic N=3 computes contributions from all nonzero input bases", async () => {
  const multi = structuredClone(key);
  multi.nPublic = 3;
  multi.IC.push([...key.IC[1]], [...key.IC[1]]);
  const h = await api.prepareRuntimeHints({
    key: api.prepareRuntimeKey(multi),
    proof,
    publicInputs: ["1", "2", "30"],
    application,
  });
  assert.deepEqual(h.claimedL, baseline.claimedL);
  assert.equal(h.magnitudes.length, 3);
  assert.notEqual(h.keyHash, baseline.keyHash);
});
test("kernel responses are length-, field- and residue-checked before use", async () => {
  await assert.rejects(
    api.prepareRuntimeHints(request(), { kernel: () => new Uint8Array(32480) }),
    /residue inverse mismatch/,
  );
  await assert.rejects(
    api.prepareRuntimeHints(request(), { kernel: () => new Uint8Array(2) }),
    /32480/,
  );
  await assert.rejects(
    api.prepareRuntimeHints(request(), {
      kernel: () => new Uint8Array(32480).fill(255),
    }),
    /noncanonical/,
  );
});
test("injected kernel is a witness source, not an application authorization boundary", async () => {
  const forged = new Uint8Array(32480);
  // c=c_inverse=w=1: inverse and subfield hold. Zero Q/blocks make the aggregate
  // check 0=0, while zero intermediate states violate the actual Miller relation.
  for (const index of [12, 24, 36]) forged[index * 32 + 31] = 1;
  const candidate = await api.prepareRuntimeHints(request(), {
    kernel: () => forged,
  });
  assert.equal(candidate.statement, BigInt(expected.statement));
  assert.notDeepEqual(api.toNoirInput(candidate.producer), expected);
});
