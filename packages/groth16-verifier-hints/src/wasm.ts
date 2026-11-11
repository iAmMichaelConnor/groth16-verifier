import {
  RUNTIME_66,
  FIXED_66,
  RUNTIME_67,
  FIXED_67,
  FIXED_68,
  RUNTIME_68,
  type CertificateSchema,
} from "./schemas.js";
/** Optional prepared-kernel protocol; no WASM payload or network fetch is bundled. */
export type PreparedKernel = (
  request: Uint8Array,
) => Uint8Array | Promise<Uint8Array>;
interface Exports {
  memory: WebAssembly.Memory;
  prepare_full(): void;
  run_full(): void;
  input_ptr(): number;
  output_ptr(): number;
}
/** Instantiate an independently supplied, trusted kernel module once. This adapter owns its instance. */
export async function createWasmKernel(
  bytes: Uint8Array,
): Promise<PreparedKernel> {
  const { instance } = await WebAssembly.instantiate(
    bytes as Uint8Array<ArrayBuffer>,
    {},
  );
  const e = instance.exports as unknown as Exports;
  for (const name of [
    "prepare_full",
    "run_full",
    "input_ptr",
    "output_ptr",
  ] as const)
    if (typeof e[name] !== "function")
      throw new Error(`Missing WASM export ${name}`);
  if (!(e.memory instanceof WebAssembly.Memory))
    throw new Error("Missing WASM memory");
  e.prepare_full();
  return (request) => {
    if (!(request instanceof Uint8Array) || request.length !== 864)
      throw new Error("Expected 864-byte prepared request");
    new Uint8Array(e.memory.buffer, e.input_ptr(), 864).set(request);
    e.run_full();
    return new Uint8Array(e.memory.buffer, e.output_ptr(), 32480).slice();
  };
}

interface VersionedExports {
  schema_mask?(): number;
  memory: WebAssembly.Memory;
  abi_version(): number;
  prepare_kernel(): void;
  run_kernel(length: number): number;
  input_ptr(): number;
  output_ptr(): number;
}
/** Explicit global66 schemas only. Neither callback accepts the later global67 format. */
export interface WasmKernels {
  readonly runtime: PreparedKernel;
  readonly fixed: PreparedKernel;
}
/**
 * Own one supplied version-1 module. Calls are synchronous inside each callback,
 * so the shared buffers cannot interleave. A trap poisons this instance: create
 * a new instance before retrying. No module is downloaded implicitly.
 */
async function versionedCallbacks(
  bytes: Uint8Array,
  requiredSchemaMask: number,
) {
  const { instance } = await WebAssembly.instantiate(
    bytes as Uint8Array<ArrayBuffer>,
    {},
  );
  const e = instance.exports as unknown as VersionedExports;
  for (const name of [
    "abi_version",
    "prepare_kernel",
    "run_kernel",
    "input_ptr",
    "output_ptr",
  ] as const)
    if (typeof e[name] !== "function")
      throw new Error(`Missing WASM export ${name}`);
  if (!(e.memory instanceof WebAssembly.Memory))
    throw new Error("Missing WASM memory");
  if (e.abi_version() !== 1) throw new Error("Unsupported WASM ABI version");
  if (
    requiredSchemaMask &&
    (typeof e.schema_mask !== "function" ||
      (e.schema_mask() & requiredSchemaMask) !== requiredSchemaMask)
  )
    throw new Error(
      `WASM module does not declare global${requiredSchemaMask >= 31 ? 68 : 67} schemas`,
    );
  e.prepare_kernel();
  let failed = false;
  const callback =
    (
      schema: number,
      inputLength: number,
      outputLength: number,
    ): PreparedKernel =>
    (request) => {
      if (failed)
        throw new Error("WASM instance failed; recreate it before retrying");
      if (!(request instanceof Uint8Array) || request.length !== inputLength)
        throw new Error(`Expected ${inputLength}-byte prepared request`);
      const header = Uint8Array.of(71, 49, 54, 72, 1, schema, 0, 0);
      try {
        const input = new Uint8Array(
          e.memory.buffer,
          e.input_ptr(),
          inputLength + 8,
        );
        input.set(header);
        input.set(request, 8);
        const length = e.run_kernel(inputLength + 8);
        if (length !== outputLength + 8)
          throw new Error("WASM response length mismatch");
        const output = new Uint8Array(e.memory.buffer, e.output_ptr(), length);
        if (!header.every((value, i) => output[i] === value))
          throw new Error("WASM response header mismatch");
        return output.slice(8);
      } catch (error) {
        failed = true;
        throw error;
      }
    };
  return (schema: CertificateSchema) =>
    callback(schema.id, schema.inputBytes, schema.outputBytes);
}

/** Backward-compatible global66 factory; works with either generation of module. */
export async function createWasmKernels(
  bytes: Uint8Array,
): Promise<WasmKernels> {
  const callback = await versionedCallbacks(bytes, 0);
  return Object.freeze({
    runtime: callback(RUNTIME_66),
    fixed: callback(FIXED_66),
  });
}
export interface PrefixWasmKernels extends WasmKernels {
  readonly runtime67: PreparedKernel;
  readonly fixed67: PreparedKernel;
}
/** Explicitly require a module that declares all four supported wire schemas. */
export async function createWasmKernels67(
  bytes: Uint8Array,
): Promise<PrefixWasmKernels> {
  const callback = await versionedCallbacks(bytes, 15);
  return Object.freeze({
    runtime: callback(RUNTIME_66),
    fixed: callback(FIXED_66),
    runtime67: callback(RUNTIME_67),
    fixed67: callback(FIXED_67),
  });
}

export interface TailWasmKernels extends PrefixWasmKernels {
  readonly fixed68: PreparedKernel;
}
/** Require IDs1..5. Only the fixed format has a68-identity successor. */
export async function createWasmKernels68(
  bytes: Uint8Array,
): Promise<TailWasmKernels> {
  const callback = await versionedCallbacks(bytes, 31);
  return Object.freeze({
    runtime: callback(RUNTIME_66),
    fixed: callback(FIXED_66),
    runtime67: callback(RUNTIME_67),
    fixed67: callback(FIXED_67),
    fixed68: callback(FIXED_68),
  });
}

export interface RuntimeTailWasmKernels extends TailWasmKernels {
  readonly runtime68: PreparedKernel;
}
/** Require IDs1..6; the earlier fixed-only68 factory retains its five callbacks. */
export async function createRuntimeWasmKernels68(
  bytes: Uint8Array,
): Promise<RuntimeTailWasmKernels> {
  const callback = await versionedCallbacks(bytes, 63);
  return Object.freeze({
    runtime: callback(RUNTIME_66),
    fixed: callback(FIXED_66),
    runtime67: callback(RUNTIME_67),
    fixed67: callback(FIXED_67),
    fixed68: callback(FIXED_68),
    runtime68: callback(RUNTIME_68),
  });
}
