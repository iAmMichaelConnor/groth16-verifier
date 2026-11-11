import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkDistribution } from "../scripts/check-dist.mjs";

test("distribution guard rejects stale output and broken public exports", async () => {
  const root = await mkdtemp(join(tmpdir(), "groth16-distribution-test-"));
  try {
    await mkdir(join(root, "src"));
    await mkdir(join(root, "dist"));
    const manifest = {
      exports: {
        ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
      },
    };
    await writeFile(join(root, "package.json"), JSON.stringify(manifest));
    await writeFile(join(root, "src/index.ts"), "export const value = 1;");
    await writeFile(join(root, "dist/index.js"), "export const value = 1;");
    await writeFile(
      join(root, "dist/index.d.ts"),
      "export declare const value = 1;",
    );
    assert.equal((await checkDistribution(root)).files, 2);
    await mkdir(join(root, "dist/src"));
    await writeFile(join(root, "dist/src/index.js"), "stale output");
    await assert.rejects(checkDistribution(root), /extra=.*src\/index.js/);
    await rm(join(root, "dist/src"), { recursive: true });
    manifest.exports["."].types = "./dist/missing.d.ts";
    await writeFile(join(root, "package.json"), JSON.stringify(manifest));
    await assert.rejects(checkDistribution(root), /Missing types export/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
