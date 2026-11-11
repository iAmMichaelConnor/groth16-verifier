// Compile into a clean temporary tree. A failed build preserves the last usable distribution.
import { mkdtemp, cp, rm, rename, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { checkDistribution } from "./check-dist.mjs";

// A sibling integration can use this same atomic build with its package root.
const root = process.argv[2]
  ? resolve(process.argv[2])
  : resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "package.json"));
const tsc = require.resolve("typescript/bin/tsc");
const output = await mkdtemp(
  join(tmpdir(), "groth16-verifier-hints-build-"),
);
try {
  const result = spawnSync(
    process.execPath,
    [tsc, "-p", join(root, "tsconfig.json"), "--outDir", output],
    {
      cwd: root,
      stdio: "inherit",
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(
      `TypeScript build failed: ${result.signal || result.status}`,
    );
  await checkDistribution(root, output);
  // Stage next to dist, then swap by rename, so a concurrent reader never sees a
  // half-copied distribution. Only the gap between the two renames has no dist.
  const staged = join(root, `dist.new-${process.pid}`);
  const previous = join(root, `dist.old-${process.pid}`);
  let moved = false;
  try {
    await cp(output, staged, { recursive: true });
    const hadDist = await access(join(root, "dist")).then(
      () => true,
      () => false,
    );
    if (hadDist) {
      await rename(join(root, "dist"), previous);
      moved = true;
    }
    await rename(staged, join(root, "dist"));
    moved = false;
  } catch (error) {
    // Put the last usable distribution back if the swap failed half way.
    if (moved) await rename(previous, join(root, "dist")).catch(() => {});
    throw error;
  } finally {
    await rm(staged, { recursive: true, force: true });
    await rm(previous, { recursive: true, force: true });
  }
  // Keep npm pack --json stdout machine-readable when this runs as prepack.
  console.error("Built and checked a clean distribution.");
} finally {
  await rm(output, { recursive: true, force: true });
}
