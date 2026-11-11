import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createWasmWorkerKernel } from "../dist/worker.js";
const profile = JSON.parse(
  fs.readFileSync(
    new URL("./fixtures/profiles/private-runtime.json", import.meta.url),
  ),
);
class FakeWorker extends EventTarget {
  terminations = 0;
  posted = [];
  reply(data) {
    this.dispatchEvent(new MessageEvent("message", { data }));
  }
  postMessage(message) {
    this.posted.push(message);
    if (message.kind === "init")
      queueMicrotask(() => this.reply({ id: message.id, ok: true }));
  }
  terminate() {
    this.terminations++;
  }
}
test("owned Worker disposes pending requests once and preserves caller input buffers", async () => {
  const worker = new FakeWorker();
  const bytes = new Uint8Array(8);
  const client = await createWasmWorkerKernel(profile, bytes, () => worker);
  assert.notEqual(worker.posted[0].bytes, bytes.buffer);
  const input = new Uint8Array(864);
  const one = client.kernel(input),
    two = client.kernel(input);
  const checks = Promise.all([
    assert.rejects(one, /disposed/),
    assert.rejects(two, /disposed/),
  ]);
  assert.notEqual(worker.posted[1].bytes, input.buffer);
  client.dispose();
  client.dispose();
  await checks;
  assert.equal(worker.terminations, 1);
  await assert.rejects(client.kernel(input), /disposed/);
  assert.equal(input.byteLength, 864);
});
test("malformed replies and operation timeout fail closed with owned cleanup", async () => {
  const worker = new FakeWorker();
  const client = await createWasmWorkerKernel(
    profile,
    new Uint8Array(),
    () => worker,
  );
  const pending = client.kernel(new Uint8Array(864));
  const rejected = assert.rejects(pending, /response bytes/);
  worker.reply({
    id: worker.posted[1].id,
    ok: true,
    output: new ArrayBuffer(1),
  });
  await rejected;
  assert.equal(worker.terminations, 1);
  const timeout = new FakeWorker();
  const slow = await createWasmWorkerKernel(
    profile,
    new Uint8Array(),
    () => timeout,
    { timeoutMs: 10 },
  );
  await assert.rejects(slow.kernel(new Uint8Array(864)), /timed out/);
  assert.equal(timeout.terminations, 1);
});
test("profile errors occur before Worker construction", async () => {
  let called = false;
  await assert.rejects(
    createWasmWorkerKernel(
      { ...profile, certificate: "wrong" },
      new Uint8Array(),
      () => {
        called = true;
        return new FakeWorker();
      },
    ),
  );
  assert.equal(called, false);
});
