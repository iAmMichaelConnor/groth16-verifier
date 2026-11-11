import type { PreparedKernel } from "groth16-verifier-hints/wasm";
import { type PreparedFixedKey } from "groth16-verifier-hints/fixed";
import { type Proof, type Integer } from "groth16-verifier-hints";
/** The SP1 circuit version whose Groth16 key and root this adapter pins. */
export declare const SP1_V6_CIRCUIT_VERSION = "v6.1.0";
/** First four bytes of sha256(groth16_vk.bin): the proof's verifier selector. */
export declare const SP1_V6_VERIFIER_SELECTOR = "4388a21c";
/** The recursion verification-key root SP1 circuit version v6.1.0 pins (public input 3). */
export declare const SP1_V6_VK_ROOT = 83960146348496814183195590144795274058764451818716359375255161226434597714n;
export declare const SP1_V6_CONFIGURATION_HASH = 15487858104255947845364280229307291878380969494329548901005093093132018200728n;
export declare function prepareSp1V6Key(): PreparedFixedKey;
export interface Sp1V6Proof {
    readonly proof: Proof;
    readonly exitCode: bigint;
    readonly vkRoot: bigint;
    readonly nonce: bigint;
}
/**
 * Parse SP1 v6 Groth16 proof bytes (`SP1ProofWithPublicValues::bytes()`): the
 * selector, exit code, vk root and nonce words, then A, B, C as eight words.
 * Rejects what SP1's onchain verifier rejects before the pairing: another
 * selector, a nonzero exit code, another vk root and a noncanonical nonce; and
 * A, B, C that are noncanonical, at infinity or off their curves (G2 subgroup
 * membership is left to the verifier).
 */
export declare function parseSp1V6ProofBytes(value: Uint8Array | string): Sp1V6Proof;
/**
 * The five public inputs SP1's v6 onchain verifier passes to the Groth16 check:
 * [program vkey, SHA256(public values) & (2^253-1), 0, SP1_V6_VK_ROOT, nonce].
 */
export declare function sp1V6PublicInputs(vkey: Integer, publicValues: Uint8Array | readonly number[], nonce: Integer): readonly [bigint, bigint, bigint, bigint, bigint];
export interface Sp1V6Request {
    readonly key?: PreparedFixedKey;
    /** SP1 v6 proof bytes, as `SP1ProofWithPublicValues::bytes()` returns them. */
    readonly proof: Uint8Array | string;
    readonly vkey: Integer;
    readonly publicValues: Uint8Array | readonly number[];
}
/**
 * Hints for sp1::v6::verify. `arguments` holds every argument of that function,
 * by parameter name, in order; pass it through `toNoirInput`.
 */
export declare function prepareSp1V6Hints(request: Sp1V6Request, options?: {
    kernel?: PreparedKernel;
}): Promise<Readonly<{
    arguments: Readonly<{
        program_vkey: bigint;
        public_values: readonly number[];
        proof_nonce: bigint;
        raw: readonly import("groth16-verifier-hints").Limb[];
        residue: readonly import("groth16-verifier-hints").Limb[];
        components: readonly (readonly bigint[])[];
        accumulators: readonly (readonly import("groth16-verifier-hints").Limb[])[];
        quotient: readonly import("groth16-verifier-hints").Limb[];
        block_residuals: readonly import("groth16-verifier-hints").Limb[];
    }>;
    schema: "groth16-fixed-global68-v1";
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
