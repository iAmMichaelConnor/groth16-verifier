import type { PreparedKernel } from "groth16-verifier-hints/wasm";
import { type PreparedFixedKey } from "groth16-verifier-hints/fixed";
import { type Proof, type Integer } from "groth16-verifier-hints";
export declare const SP1_CONFIGURATION_HASH = 11610070592383739928887964744989344216464605173011498513140240201529586530148n;
export declare function prepareSp1Key(): PreparedFixedKey;
/** Exact pinned SP1 v5 proof selector; other verifier revisions require their own configuration. */
export declare const SP1_VERIFIER_SELECTOR = "a4594c59";
export declare function parseSp1ProofBytes(value: Uint8Array | string): Proof;
/** SP1-specific convention: [program vkey, SHA256(public values) masked to 253 bits]. */
export declare function sp1PublicInputs(vkey: Integer, publicValues: Uint8Array | readonly number[]): readonly [bigint, bigint];
/**
 * Fixed-SP1 private-call arguments, capsules and the offchain producer inputs.
 * `statement` = Poseidon2("GR16_SINGLE_V6\x01", application[6], vkey,
 * publicValues[32]) is an SP1-specific statement schema. No Noir circuit in this
 * repository computes it; treat it as unauthenticated host
 * metadata unless a consumer circuit recomputes it with this exact layout.
 */
declare function prepareSp1(request: {
    key?: PreparedFixedKey;
    proof: unknown;
    vkey: Integer;
    publicValues: Uint8Array | readonly number[];
    application: readonly Integer[];
}, options: {
    kernel?: PreparedKernel;
}, format: 66 | 67 | 68): Promise<Readonly<{
    statement: bigint;
    application: readonly bigint[];
    arguments: Readonly<{
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
    }>;
    producer: Readonly<{
        glv_components: readonly (readonly bigint[])[];
        accumulators: readonly (readonly import("groth16-verifier-hints").Limb[])[];
        quotient: readonly import("groth16-verifier-hints").Limb[];
        block_residuals: readonly import("groth16-verifier-hints").Limb[];
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
        statement: bigint;
        application: readonly bigint[];
    }>;
    inputCount: number;
    configurationHash: bigint;
    publicInputs: readonly bigint[];
    raw: readonly import("groth16-verifier-hints").Limb[];
    residue: readonly import("groth16-verifier-hints").Limb[];
    glvComponents: readonly (readonly bigint[])[];
    accumulators: import("groth16-verifier-hints").PairingHints["accumulators"];
    quotient: readonly import("groth16-verifier-hints").Limb[];
    blockResiduals: readonly import("groth16-verifier-hints").Limb[];
    capsules: {
        readonly private: readonly import("groth16-verifier-hints").Capsule[];
    };
}>>;
export type Sp1Request = Parameters<typeof prepareSp1>[0];
export type Sp1Options = Parameters<typeof prepareSp1>[1];
export declare function prepareSp1Hints(request: Sp1Request, options?: Sp1Options): Promise<Readonly<{
    statement: bigint;
    application: readonly bigint[];
    arguments: Readonly<{
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
    }>;
    producer: Readonly<{
        glv_components: readonly (readonly bigint[])[];
        accumulators: readonly (readonly import("groth16-verifier-hints").Limb[])[];
        quotient: readonly import("groth16-verifier-hints").Limb[];
        block_residuals: readonly import("groth16-verifier-hints").Limb[];
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
        statement: bigint;
        application: readonly bigint[];
    }>;
    inputCount: number;
    configurationHash: bigint;
    publicInputs: readonly bigint[];
    raw: readonly import("groth16-verifier-hints").Limb[];
    residue: readonly import("groth16-verifier-hints").Limb[];
    glvComponents: readonly (readonly bigint[])[];
    accumulators: import("groth16-verifier-hints").PairingHints["accumulators"];
    quotient: readonly import("groth16-verifier-hints").Limb[];
    blockResiduals: readonly import("groth16-verifier-hints").Limb[];
    capsules: {
        readonly private: readonly import("groth16-verifier-hints").Capsule[];
    };
}>>;
export declare function prepareSp1Hints67(request: Sp1Request, options?: Sp1Options): Promise<Readonly<{
    schema: "groth16-fixed-global67-v1";
    statement: bigint;
    application: readonly bigint[];
    arguments: Readonly<{
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
    }>;
    producer: Readonly<{
        glv_components: readonly (readonly bigint[])[];
        accumulators: readonly (readonly import("groth16-verifier-hints").Limb[])[];
        quotient: readonly import("groth16-verifier-hints").Limb[];
        block_residuals: readonly import("groth16-verifier-hints").Limb[];
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
        statement: bigint;
        application: readonly bigint[];
    }>;
    inputCount: number;
    configurationHash: bigint;
    publicInputs: readonly bigint[];
    raw: readonly import("groth16-verifier-hints").Limb[];
    residue: readonly import("groth16-verifier-hints").Limb[];
    glvComponents: readonly (readonly bigint[])[];
    accumulators: import("groth16-verifier-hints").PairingHints["accumulators"];
    quotient: readonly import("groth16-verifier-hints").Limb[];
    blockResiduals: readonly import("groth16-verifier-hints").Limb[];
    capsules: {
        readonly private: readonly import("groth16-verifier-hints").Capsule[];
    };
}>>;
export declare function prepareSp1Hints68(request: Sp1Request, options?: Sp1Options): Promise<Readonly<{
    schema: "groth16-fixed-global68-v1";
    statement: bigint;
    application: readonly bigint[];
    arguments: Readonly<{
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
    }>;
    producer: Readonly<{
        glv_components: readonly (readonly bigint[])[];
        accumulators: readonly (readonly import("groth16-verifier-hints").Limb[])[];
        quotient: readonly import("groth16-verifier-hints").Limb[];
        block_residuals: readonly import("groth16-verifier-hints").Limb[];
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        vkey: bigint;
        public_values: readonly number[];
        statement: bigint;
        application: readonly bigint[];
    }>;
    inputCount: number;
    configurationHash: bigint;
    publicInputs: readonly bigint[];
    raw: readonly import("groth16-verifier-hints").Limb[];
    residue: readonly import("groth16-verifier-hints").Limb[];
    glvComponents: readonly (readonly bigint[])[];
    accumulators: import("groth16-verifier-hints").PairingHints["accumulators"];
    quotient: readonly import("groth16-verifier-hints").Limb[];
    blockResiduals: readonly import("groth16-verifier-hints").Limb[];
    capsules: {
        readonly private: readonly import("groth16-verifier-hints").Capsule[];
    };
}>>;
export * from "./v6.js";
