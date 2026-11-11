/** Strict snarkjs BN254 wire parsing. Never use Number for field elements. */
export type Integer = string | bigint;
export type G1 = readonly [bigint, bigint];
export type G2 = readonly [G1, G1];
export declare const FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export declare const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export interface VerificationKey {
    readonly protocol: "groth16";
    readonly curve: "bn128";
    readonly nPublic: number;
    readonly vk_alpha_1: G1;
    readonly vk_beta_2: G2;
    readonly vk_gamma_2: G2;
    readonly vk_delta_2: G2;
    readonly IC: readonly G1[];
}
export interface Proof {
    readonly protocol: "groth16";
    readonly curve: "bn128";
    readonly pi_a: G1;
    readonly pi_b: G2;
    readonly pi_c: G1;
}
export declare function integer(value: unknown, modulus: bigint, label: string): bigint;
export declare function tuple(value: unknown, size: number, label: string): unknown[];
/**
 * Encoding checks plus key relations: delta must differ from +-gamma and from
 * +-the G2 generator, and at least one IC point must be finite. prepareRuntimeKey /
 * prepareRuntimeHints also check curve and subgroup membership.
 */
export declare function parseVerificationKey(value: unknown): VerificationKey;
export declare function parseProof(value: unknown): Proof;
