import { type CertificateSchema } from "./schemas.js";
import { FR, FQ, parseVerificationKey, parseProof, type Integer } from "./parsers.js";
import { decomposeScalar } from "./glv.js";
import type { PreparedKernel } from "./wasm.js";
export { parseVerificationKey, parseProof, FR, FQ, decomposeScalar };
export type { Integer, VerificationKey, Proof } from "./parsers.js";
export type { PreparedKernel } from "./wasm.js";
export type Limb = readonly [bigint, bigint, bigint];
export type RawG1 = readonly [Limb, Limb];
export interface RawVerificationKey {
    readonly alpha: RawG1;
    readonly beta: readonly Limb[];
    readonly gamma: readonly Limb[];
    readonly delta: readonly Limb[];
    readonly ic: readonly RawG1[];
}
export declare const CAPSULE_BASE: bigint;
declare const preparedBrand: unique symbol;
export interface PreparedKey {
    readonly inputCount: number;
    readonly keyHash: bigint;
    readonly [preparedBrand]: true;
}
export declare function prepareRuntimeKey(value: unknown): PreparedKey;
export interface PairingHints {
    readonly residue: readonly Limb[];
    readonly accumulators: readonly (readonly Limb[])[];
    readonly quotient: readonly Limb[];
    readonly block_residuals: readonly Limb[];
}
export interface Capsule {
    readonly scope: bigint;
    readonly slot: bigint;
    readonly values: readonly bigint[];
}
export interface RuntimeHints {
    readonly inputCount: number;
    readonly keyHash: bigint;
    readonly statement: bigint;
    readonly application: readonly bigint[];
    readonly key: RawVerificationKey;
    readonly flatKey: readonly Limb[];
    readonly publicInputs: readonly bigint[];
    readonly proof: readonly Limb[];
    readonly claimedL: RawG1;
    readonly magnitudes: readonly (readonly bigint[])[];
    readonly negative: readonly (readonly boolean[])[];
    readonly pairing: PairingHints;
    readonly capsules: {
        readonly private: readonly Capsule[];
    };
    readonly producer: Readonly<Record<string, unknown>>;
}
/** Complete runtime-key preparation. Outputs remain untrusted witnesses checked by Noir. */
declare function prepareRuntime(request: {
    key: PreparedKey;
    proof: unknown;
    publicInputs: readonly Integer[];
    application: readonly Integer[];
}, options: {
    kernel?: PreparedKernel;
}, schema: CertificateSchema): Promise<RuntimeHints>;
export type RuntimeRequest = Parameters<typeof prepareRuntime>[0];
export type RuntimeOptions = Parameters<typeof prepareRuntime>[1];
export declare function prepareRuntimeHints(request: RuntimeRequest, options?: RuntimeOptions): Promise<RuntimeHints>;
export declare function prepareRuntimeHints67(request: RuntimeRequest, options?: RuntimeOptions): Promise<Readonly<{
    schema: "groth16-runtime-global67-v1";
    inputCount: number;
    keyHash: bigint;
    statement: bigint;
    application: readonly bigint[];
    key: RawVerificationKey;
    flatKey: readonly Limb[];
    publicInputs: readonly bigint[];
    proof: readonly Limb[];
    claimedL: RawG1;
    magnitudes: readonly (readonly bigint[])[];
    negative: readonly (readonly boolean[])[];
    pairing: PairingHints;
    capsules: {
        readonly private: readonly Capsule[];
    };
    producer: Readonly<Record<string, unknown>>;
}>>;
export declare const PREFIX_CAPSULE_BASE: bigint;
export declare function prepareRuntimeHints68(request: RuntimeRequest, options?: RuntimeOptions): Promise<Readonly<{
    schema: "groth16-runtime-global68-v1";
    inputCount: number;
    keyHash: bigint;
    statement: bigint;
    application: readonly bigint[];
    key: RawVerificationKey;
    flatKey: readonly Limb[];
    publicInputs: readonly bigint[];
    proof: readonly Limb[];
    claimedL: RawG1;
    magnitudes: readonly (readonly bigint[])[];
    negative: readonly (readonly boolean[])[];
    pairing: PairingHints;
    capsules: {
        readonly private: readonly Capsule[];
    };
    producer: Readonly<Record<string, unknown>>;
}>>;
export declare const TAIL_CAPSULE_BASE: bigint;
/** Check concrete contract arity explicitly. The supplied examples currently use N=1. */
export declare function privateCallArguments(hints: RuntimeHints, expectedInputCount: number): {
    key: readonly Limb[];
    public_inputs: readonly bigint[];
    proof: readonly Limb[];
};
/** Lossless JSON-compatible data for Noir input tooling. BigInts become decimal strings. */
export declare function toNoirInput(value: unknown): unknown;
