import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { createVerifier, profileHash } from "../dist/current.js";
import { prepareRuntimeKey, FR } from "../dist/index.js";
import {
  createProducer,
  decodeFields,
  assertProducerCertificate,
} from "../dist/producer.js";
import { prepareOffchainCall } from "../dist/aztec.js";
const read = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url)));
const vk = read("../../../fixtures/multiplier/verification_key.json"),
  proof = read("../../../fixtures/multiplier/proof.json");
const profile = read("./fixtures/profiles/offchain-runtime.json");
profile.keyHash = prepareRuntimeKey(vk).keyHash.toString();
const sha = (b) => createHash("sha256").update(b).digest("hex");
const fieldBytes = (values) =>
  Uint8Array.from(
    Buffer.from(
      values.map((n) => n.toString(16).padStart(64, "0")).join(""),
      "hex",
    ),
  );
const keyBytes = fieldBytes([18n, 9n, ...Array(113).fill(0n)]);
const artifactBytes = Buffer.from(
  JSON.stringify({
    bytecode: Buffer.from([1, 2, 3]).toString("base64"),
    abi: {},
  }),
);
const identity = {
  role: "producer",
  artifactSha256: sha(artifactBytes),
  bytecodeSha256: sha(Uint8Array.of(1, 2, 3)),
  verificationKeySha256: sha(keyBytes),
};
const manifest = {
  schema: "groth16-verifier-artifacts-v1",
  profileSha256: profileHash(profile),
  artifacts: [identity, { ...identity, role: "private-consumer" }],
};
// Deliberately fake backend tests only host sequencing and formats, never proof validity.
let packet;
async function setup(delta = {}) {
  packet ??= await createVerifier(profile, vk).prepare({
    proof,
    publicInputs: ["33"],
    application: ["1", "1", "7", "11", "13", "17"],
  });
  const calls = [];
  const backend = {
    getVerificationKey: async (options) => {
      calls.push(["key", options]);
      return keyBytes;
    },
    generateProof: async (witness, options) => {
      calls.push(["prove", options]);
      return {
        proof: fieldBytes(Array(458).fill(0n)),
        publicInputs: [packet.statement.toString()],
      };
    },
    verifyProof: async (data, options) => {
      calls.push(["verify", options]);
      return true;
    },
    ...delta,
  };
  const executor = {
    execute: async (inputs) => {
      calls.push(["execute", inputs.statement]);
      return { witness: Uint8Array.of(9) };
    },
  };
  const options = {
    profile,
    artifactBytes,
    manifest,
    backend: () => backend,
    executor: () => executor,
  };
  return { options, calls, backend };
}
test("producer authenticates artifact and key before witness generation and proves only explicitly", async () => {
  const { options, calls } = await setup();
  const producer = await createProducer(options);
  assert.deepEqual(
    calls.map((c) => c[0]),
    ["key"],
  );
  const certificate = await producer.prove(packet);
  assert.deepEqual(
    calls.map((c) => c[0]),
    ["key", "execute", "prove", "verify"],
  );
  assert.equal(certificate.statement, packet.statement);
  assert.equal(certificate.proof.length, 458);
  assertProducerCertificate(profile, packet, certificate);
  assert.throws(
    () => assertProducerCertificate(profile, packet, { ...certificate }),
    /mismatch/,
  );
  const contract = {
    address: { toField: () => ({ toBigInt: () => 7n }) },
    methods: {
      verify: (...args) => ({
        args,
        with() {
          return this;
        },
      }),
    },
  };
  assert.equal(
    prepareOffchainCall(
      profile,
      packet,
      certificate,
      contract,
      certificate.producerKeyHash,
    ).args[3],
    certificate.producerKey,
  );
  assert.throws(
    () => prepareOffchainCall(profile, packet, certificate, contract, 0n),
    /Unapproved/,
  );
});
test("producer rejects stale bytes, unapproved keys, incompatible shapes and unverified proofs", async () => {
  const { options, calls } = await setup();
  await assert.rejects(
    () => createProducer({ ...options, artifactBytes: Buffer.from("{}") }),
    /artifact digest/,
  );
  assert.equal(calls.length, 0);
  await assert.rejects(
    () =>
      createProducer({
        ...options,
        manifest: {
          ...manifest,
          artifacts: [
            { ...identity, verificationKeySha256: null },
            manifest.artifacts[1],
          ],
        },
      }),
    /Approve/,
  );
  await assert.rejects(
    () =>
      createProducer({
        ...options,
        backend: () => ({
          ...options.backend(),
          getVerificationKey: async () => fieldBytes(Array(115).fill(0n)),
        }),
      }),
    /key digest/,
  );
  for (const override of [
    {
      generateProof: async () => ({
        proof: fieldBytes(Array(458).fill(0n)),
        publicInputs: ["0"],
      }),
    },
    {
      generateProof: async () => ({
        proof: new Uint8Array(1),
        publicInputs: [packet.statement.toString()],
      }),
    },
    { verifyProof: async () => false },
  ]) {
    const x = await setup(override);
    const producer = await createProducer(x.options);
    await assert.rejects(() => producer.prove(packet));
  }
  assert.throws(() => decodeFields(fieldBytes([FR]), 1), /noncanonical/);
  assert.throws(() => decodeFields(new Uint8Array(31), 1), /field words/);
});
