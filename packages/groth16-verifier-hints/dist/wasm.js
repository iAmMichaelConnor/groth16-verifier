import { RUNTIME_66, FIXED_66, RUNTIME_67, FIXED_67, FIXED_68, RUNTIME_68, } from "./schemas.js";
/** Instantiate an independently supplied, trusted kernel module once. This adapter owns its instance. */
export async function createWasmKernel(bytes) {
    const { instance } = await WebAssembly.instantiate(bytes, {});
    const e = instance.exports;
    for (const name of [
        "prepare_full",
        "run_full",
        "input_ptr",
        "output_ptr",
    ])
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
/**
 * Own one supplied version-1 module. Calls are synchronous inside each callback,
 * so the shared buffers cannot interleave. A trap poisons this instance: create
 * a new instance before retrying. No module is downloaded implicitly.
 */
async function versionedCallbacks(bytes, requiredSchemaMask) {
    const { instance } = await WebAssembly.instantiate(bytes, {});
    const e = instance.exports;
    for (const name of [
        "abi_version",
        "prepare_kernel",
        "run_kernel",
        "input_ptr",
        "output_ptr",
    ])
        if (typeof e[name] !== "function")
            throw new Error(`Missing WASM export ${name}`);
    if (!(e.memory instanceof WebAssembly.Memory))
        throw new Error("Missing WASM memory");
    if (e.abi_version() !== 1)
        throw new Error("Unsupported WASM ABI version");
    if (requiredSchemaMask &&
        (typeof e.schema_mask !== "function" ||
            (e.schema_mask() & requiredSchemaMask) !== requiredSchemaMask))
        throw new Error(`WASM module does not declare global${requiredSchemaMask >= 31 ? 68 : 67} schemas`);
    e.prepare_kernel();
    let failed = false;
    const callback = (schema, inputLength, outputLength) => (request) => {
        if (failed)
            throw new Error("WASM instance failed; recreate it before retrying");
        if (!(request instanceof Uint8Array) || request.length !== inputLength)
            throw new Error(`Expected ${inputLength}-byte prepared request`);
        const header = Uint8Array.of(71, 49, 54, 72, 1, schema, 0, 0);
        try {
            const input = new Uint8Array(e.memory.buffer, e.input_ptr(), inputLength + 8);
            input.set(header);
            input.set(request, 8);
            const length = e.run_kernel(inputLength + 8);
            if (length !== outputLength + 8)
                throw new Error("WASM response length mismatch");
            const output = new Uint8Array(e.memory.buffer, e.output_ptr(), length);
            if (!header.every((value, i) => output[i] === value))
                throw new Error("WASM response header mismatch");
            return output.slice(8);
        }
        catch (error) {
            failed = true;
            throw error;
        }
    };
    return (schema) => callback(schema.id, schema.inputBytes, schema.outputBytes);
}
/** Backward-compatible global66 factory; works with either generation of module. */
export async function createWasmKernels(bytes) {
    const callback = await versionedCallbacks(bytes, 0);
    return Object.freeze({
        runtime: callback(RUNTIME_66),
        fixed: callback(FIXED_66),
    });
}
/** Explicitly require a module that declares all four supported wire schemas. */
export async function createWasmKernels67(bytes) {
    const callback = await versionedCallbacks(bytes, 15);
    return Object.freeze({
        runtime: callback(RUNTIME_66),
        fixed: callback(FIXED_66),
        runtime67: callback(RUNTIME_67),
        fixed67: callback(FIXED_67),
    });
}
/** Require IDs1..5. Only the fixed format has a68-identity successor. */
export async function createWasmKernels68(bytes) {
    const callback = await versionedCallbacks(bytes, 31);
    return Object.freeze({
        runtime: callback(RUNTIME_66),
        fixed: callback(FIXED_66),
        runtime67: callback(RUNTIME_67),
        fixed67: callback(FIXED_67),
        fixed68: callback(FIXED_68),
    });
}
/** Require IDs1..6; the earlier fixed-only68 factory retains its five callbacks. */
export async function createRuntimeWasmKernels68(bytes) {
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
