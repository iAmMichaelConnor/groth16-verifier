import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generic = resolve(root, "../groth16-verifier-hints");
function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout: 120000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result.stdout;
}
test("both packed packages work outside the checkout with public imports only", async () => {
  const work = await mkdtemp(join(tmpdir(), "sp1-consumer-"));
  try {
    const archives = [];
    for (const directory of [generic, root]) {
      const packed = JSON.parse(
        run(
          "npm",
          ["pack", "--ignore-scripts", "--json", "--pack-destination", work],
          directory,
        ),
      );
      archives.push(join(work, packed[0].filename));
    }
    const consumer = join(work, "consumer");
    await mkdir(consumer);
    await writeFile(
      join(consumer, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    run(
      "npm",
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--prefer-offline",
        ...archives,
      ],
      consumer,
    );
    await writeFile(
      join(consumer, "fixture.json"),
      await readFile(join(root, "test/fixtures/fixed-sp1.json")),
    );
    await writeFile(
      join(consumer, "check.mjs"),
      `
import assert from "node:assert/strict";
import fs from "node:fs";
import { prepareSp1Key, prepareSp1Hints68, prepareSp1V6Key, SP1_V6_CONFIGURATION_HASH } from "groth16-verifier-sp1";
import { poseidon2Hash } from "groth16-verifier-hints/transcript";
const fixture = JSON.parse(fs.readFileSync(new URL("./fixture.json", import.meta.url)));
const hints = await prepareSp1Hints68({ ...fixture, key: prepareSp1Key() });
assert.equal(hints.schema, "groth16-fixed-global68-v1");
assert.equal(hints.statement.toString(), fixture.expected.statement);
assert.equal(hints.statement, poseidon2Hash([0x475231365f53494e474c455f563601n, ...fixture.application, fixture.vkey, ...fixture.publicValues.map(BigInt)]));
await assert.rejects(import("groth16-verifier-hints/sp1"), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
assert.equal(prepareSp1V6Key().configurationHash, SP1_V6_CONFIGURATION_HASH);
`,
    );
    run(process.execPath, ["check.mjs"], consumer);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});
