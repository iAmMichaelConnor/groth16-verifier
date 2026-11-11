// Reuse the generic SDK's atomic TypeScript build and distribution guard.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const build = resolve(root, "../groth16-verifier-hints/scripts/build.mjs");
const result = spawnSync(process.execPath, [build, root], { stdio: "inherit" });
if (result.error) throw result.error;
if (result.status !== 0)
  throw new Error(`SDK build failed: ${result.signal || result.status}`);
