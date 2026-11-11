/** Optional prepared-kernel protocol; no WASM payload or network fetch is bundled. */
export type PreparedKernel = (request: Uint8Array) => Uint8Array | Promise<Uint8Array>;
/** Instantiate an independently supplied, trusted kernel module once. This adapter owns its instance. */
export declare function createWasmKernel(bytes: Uint8Array): Promise<PreparedKernel>;
/** Explicit global66 schemas only. Neither callback accepts the later global67 format. */
export interface WasmKernels {
    readonly runtime: PreparedKernel;
    readonly fixed: PreparedKernel;
}
/** Backward-compatible global66 factory; works with either generation of module. */
export declare function createWasmKernels(bytes: Uint8Array): Promise<WasmKernels>;
export interface PrefixWasmKernels extends WasmKernels {
    readonly runtime67: PreparedKernel;
    readonly fixed67: PreparedKernel;
}
/** Explicitly require a module that declares all four supported wire schemas. */
export declare function createWasmKernels67(bytes: Uint8Array): Promise<PrefixWasmKernels>;
export interface TailWasmKernels extends PrefixWasmKernels {
    readonly fixed68: PreparedKernel;
}
/** Require IDs1..5. Only the fixed format has a68-identity successor. */
export declare function createWasmKernels68(bytes: Uint8Array): Promise<TailWasmKernels>;
export interface RuntimeTailWasmKernels extends TailWasmKernels {
    readonly runtime68: PreparedKernel;
}
/** Require IDs1..6; the earlier fixed-only68 factory retains its five callbacks. */
export declare function createRuntimeWasmKernels68(bytes: Uint8Array): Promise<RuntimeTailWasmKernels>;
