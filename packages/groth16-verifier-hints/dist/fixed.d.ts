import { type CertificateSchema } from "./schemas.js";
import { type Integer } from "./parsers.js";
import type { Limb, PairingHints, Capsule } from "./index.js";
import type { PreparedKernel } from "./wasm.js";
export declare const FIXED_CAPSULE_BASE: bigint;
export interface FixedKeyDescriptor {
    readonly schema: "groth16-fixed-global66-v1";
    readonly verificationKey: unknown;
    readonly tPreimage: readonly Integer[];
}
declare const fixedBrand: unique symbol;
export interface PreparedFixedKey {
    readonly inputCount: number;
    readonly keyHash: bigint;
    readonly configurationHash: bigint;
    readonly [fixedBrand]: true;
}
/** Developer setup helper, not approval: compare this identity with the manifest for the compiled consumer. */
export declare function fixedConfigurationHash(descriptor: FixedKeyDescriptor): bigint;
/** Host mismatch guard. It does not replace the application's on-chain key/statement policy. */
export declare function prepareFixedKey(descriptor: FixedKeyDescriptor, expectedConfigurationHash: Integer): PreparedFixedKey;
export interface FixedHints {
    readonly inputCount: number;
    readonly configurationHash: bigint;
    readonly publicInputs: readonly bigint[];
    readonly raw: readonly Limb[];
    readonly residue: readonly Limb[];
    readonly glvComponents: readonly (readonly bigint[])[];
    readonly accumulators: PairingHints["accumulators"];
    readonly quotient: readonly Limb[];
    readonly blockResiduals: readonly Limb[];
    readonly capsules: {
        readonly private: readonly Capsule[];
    };
}
/** Generic fixed-key arithmetic inputs. Application/producer statement schemas are deliberately separate. */
declare function prepareFixed(request: {
    key: PreparedFixedKey;
    proof: unknown;
    publicInputs: readonly Integer[];
}, options: {
    kernel?: PreparedKernel;
}, schema: CertificateSchema): Promise<FixedHints>;
export type FixedRequest = Parameters<typeof prepareFixed>[0];
export type FixedOptions = Parameters<typeof prepareFixed>[1];
export declare function prepareFixedHints(request: FixedRequest, options?: FixedOptions): Promise<FixedHints>;
export declare function prepareFixedHints67(request: FixedRequest, options?: FixedOptions): Promise<Readonly<{
    schema: "groth16-fixed-global67-v1";
    inputCount: number;
    configurationHash: bigint;
    publicInputs: readonly bigint[];
    raw: readonly Limb[];
    residue: readonly Limb[];
    glvComponents: readonly (readonly bigint[])[];
    accumulators: PairingHints["accumulators"];
    quotient: readonly Limb[];
    blockResiduals: readonly Limb[];
    capsules: {
        readonly private: readonly Capsule[];
    };
}>>;
export declare const FIXED_PREFIX_CAPSULE_BASE: bigint;
/**
 * Fixed-only terminal split. No runtime68 format is implied.
 * The common capsule (2,631 fields: accumulators, quotient, residuals) is the
 * explicit-residue layout; pass `residue` as a separate argument. Scaffolded
 * wrappers expect the 2,739-field residue-prefixed capsule from `/current`
 * `createVerifier` in the same slot, so do not send these capsules to them.
 */
export declare function prepareFixedHints68(request: FixedRequest, options?: FixedOptions): Promise<Readonly<{
    schema: "groth16-fixed-global68-v1";
    inputCount: number;
    configurationHash: bigint;
    publicInputs: readonly bigint[];
    raw: readonly Limb[];
    residue: readonly Limb[];
    glvComponents: readonly (readonly bigint[])[];
    accumulators: PairingHints["accumulators"];
    quotient: readonly Limb[];
    blockResiduals: readonly Limb[];
    capsules: {
        readonly private: readonly Capsule[];
    };
}>>;
export declare const FIXED_TAIL_CAPSULE_BASE: bigint;
export {};
