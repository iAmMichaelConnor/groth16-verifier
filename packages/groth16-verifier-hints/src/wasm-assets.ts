/** Optional authenticated asset loading. Importing this module never fetches or instantiates WASM. */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { parseProfile } from "./current.js";
import { createRuntimeWasmKernels68, type PreparedKernel } from "./wasm.js";

export const HINTS_WASM_V1 = Object.freeze({
  schema: "groth16-verifier-hints-wasm-asset-v1" as const,
  package: "groth16-verifier-hints-wasm",
  path: "v1/hints-kernel.wasm",
  sha256: "7d26252af3c97a54b5a9f27f4ead6b7317ea0ca7b637d98affdd711f242dd2d0",
  bytes: 471268,
  capabilityMask: 63,
});

/** Verify exact maintained asset bytes, then select the kernel required by the approved profile.
 * The digest authenticates this release asset; generated hints still require circuit verification.
 */
export async function createProfileWasmKernel(
  profile: unknown,
  bytes: Uint8Array,
): Promise<PreparedKernel> {
  const parsed = parseProfile(profile);
  if (!(bytes instanceof Uint8Array) || bytes.length !== HINTS_WASM_V1.bytes) {
    throw new Error(
      `Wrong hints WASM v1 asset length; expected ${HINTS_WASM_V1.bytes} bytes`,
    );
  }
  // Own the bytes across the asynchronous WebAssembly boundary; callers can mutate their buffers.
  const owned = Uint8Array.from(bytes);
  if (bytesToHex(sha256(owned)) !== HINTS_WASM_V1.sha256) {
    throw new Error(
      "Wrong hints WASM v1 SHA256; use the matching versioned asset",
    );
  }
  const kernels = await createRuntimeWasmKernels68(owned);
  return parsed.keyPolicy === "fixed" ? kernels.fixed68 : kernels.runtime68;
}
