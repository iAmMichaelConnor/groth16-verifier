import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createVerifier } from "../dist/current.js";
import { prepareRuntimeKey } from "../dist/index.js";
import { preparePrivateCall } from "../dist/aztec.js";
const read = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url)));
const vk = read("../../../fixtures/multiplier/verification_key.json");
const proof = read("../../../fixtures/multiplier/proof.json");
const profile = read("./fixtures/profiles/private-runtime.json");
profile.keyHash = prepareRuntimeKey(vk).keyHash.toString();
class Fr {
  constructor(n) {
    this.n = n;
  }
  toBigInt() {
    return this.n;
  }
}
class AztecAddress {
  constructor(f) {
    this.f = f;
  }
  static fromField(f) {
    return new this(f);
  }
  toField() {
    return this.f;
  }
}
class Capsule {
  constructor(contractAddress, storageSlot, data, scope) {
    Object.assign(this, { contractAddress, storageSlot, data, scope });
  }
}
AztecAddress.ZERO = AztecAddress.fromField(new Fr(0n));
const sdk = { Fr, AztecAddress, Capsule };
test("private call scopes capsules and preserves contract ABI without submitting", async () => {
  const packet = await createVerifier(profile, vk).prepare({
    proof,
    publicInputs: ["33"],
    application: ["1", "1", "7", "11", "13", "17"],
  });
  let calls = 0;
  const contract = {
    address: AztecAddress.fromField(new Fr(7n)),
    methods: {
      verify(...args) {
        calls++;
        return { with: ({ capsules }) => ({ args, capsules }) };
      },
    },
  };
  const result = preparePrivateCall(profile, packet, contract, sdk);
  assert.equal(calls, 1);
  assert.equal(result.args[0], packet.statement);
  assert.equal(result.args[3], packet.hints.flatKey);
  assert.equal(result.capsules.length, 2);
  assert.equal(result.capsules[0].contractAddress, contract.address);
  assert.equal(result.capsules[0].scope.toField().toBigInt(), 0n);
  assert.deepEqual(
    result.capsules[1].data.map((x) => x.toBigInt()),
    packet.capsules[1].values,
  );
  assert.throws(
    () =>
      preparePrivateCall(
        profile,
        packet,
        { ...contract, address: AztecAddress.fromField(new Fr(8n)) },
        sdk,
      ),
    /address mismatch/,
  );
  assert.throws(
    () => preparePrivateCall(profile, { ...packet }, contract, sdk),
    /mismatch/,
  );
  assert.equal(calls, 1);
});
