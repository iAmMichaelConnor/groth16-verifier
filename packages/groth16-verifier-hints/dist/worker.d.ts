import type { PreparedKernel } from "./wasm.js";
export interface OwnedWorkerKernel {
    readonly kernel: PreparedKernel;
    /** Idempotent: rejects pending work and terminates only this client's owned Worker. */
    dispose(): void;
}
/** The factory must create a NEW dedicated Worker, whose ownership transfers to this client.
 * Caller buffers are copied before transfer. No Worker, fetch or WASM load occurs on import.
 */
export declare function createWasmWorkerKernel(profile: unknown, bytes: Uint8Array, workerFactory: () => Worker, options?: {
    timeoutMs?: number;
}): Promise<OwnedWorkerKernel>;
