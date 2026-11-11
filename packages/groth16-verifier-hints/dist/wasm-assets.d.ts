import { type PreparedKernel } from "./wasm.js";
export declare const HINTS_WASM_V1: Readonly<{
    schema: "groth16-verifier-hints-wasm-asset-v1";
    package: "groth16-verifier-hints-wasm";
    path: "v1/hints-kernel.wasm";
    sha256: "7d26252af3c97a54b5a9f27f4ead6b7317ea0ca7b637d98affdd711f242dd2d0";
    bytes: 471268;
    capabilityMask: 63;
}>;
/** Verify exact maintained asset bytes, then select the kernel required by the approved profile.
 * The digest authenticates this release asset; generated hints still require circuit verification.
 */
export declare function createProfileWasmKernel(profile: unknown, bytes: Uint8Array): Promise<PreparedKernel>;
