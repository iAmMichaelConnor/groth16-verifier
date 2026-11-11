import { prepareRuntimeHints68, type Capsule, type RuntimeOptions } from "./index.js";
import { prepareFixedHints68 } from "./fixed.js";
import { type Integer } from "./parsers.js";
export interface ConsumerProfile {
    readonly schema: "groth16-verifier-profile-v2";
    readonly name: string;
    readonly mode: "private" | "offchain";
    readonly keyPolicy: "fixed" | "runtime";
    readonly inputCount: number;
    readonly certificate: "groth16-fixed-global68-v1" | "groth16-runtime-global68-v1";
    readonly keyHash: string;
    readonly configurationHash: string | null;
    readonly statementSchema: "groth16-verifier-statement-v1";
    readonly toolchain: {
        readonly aztecCommit: typeof STOCK_AZTEC;
        readonly noirCommit: typeof NOIR;
        readonly backend: "stock-v6";
    };
    readonly domain: "finite-pairing-operands-v1";
}
export interface CurrentFixedKeyDescriptor {
    readonly schema: "groth16-fixed-key-v1";
    readonly verificationKey: unknown;
    readonly tPreimage: readonly Integer[];
}
/** Stock Aztec v6.0.0 release (aztec-packages tag v6.0.0). */
declare const STOCK_AZTEC = "0219f11d8133970df3974fe5ae65e006bf8c193a";
declare const NOIR = "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7";
/** Validate and copy before hashing or invoking any arithmetic backend. */
export declare function parseProfile(value: unknown): ConsumerProfile;
export declare function profileHash(value: unknown): string;
/** Same Poseidon2 preimage as schema::statement_id<N>. Context binding does not
 * establish that the original Groth16 circuit authenticated that context. */
export declare function statementId(profile: unknown, application: readonly Integer[], publicInputs: readonly Integer[]): bigint;
type CurrentHints = Awaited<ReturnType<typeof prepareFixedHints68>> | Awaited<ReturnType<typeof prepareRuntimeHints68>>;
export interface PreparedRequest {
    readonly profileSha256: string;
    readonly statement: bigint;
    readonly application: readonly bigint[];
    readonly publicInputs: readonly bigint[];
    readonly hints: CurrentHints;
    readonly capsules: readonly Capsule[];
    readonly callArguments: Readonly<Record<string, unknown>>;
    readonly producerInputs: Readonly<Record<string, unknown>>;
}
/** Reject cross-profile packets, including structurally forged plain objects. */
export declare function assertPreparedRequest(profile: unknown, packet: PreparedRequest): void;
export interface PrepareRequest {
    readonly proof: unknown;
    readonly publicInputs: readonly Integer[];
    readonly application: readonly Integer[];
}
/** An optional backend declaration must match the profile's backend. */
export declare function createVerifier(profile: unknown, keyMaterial: unknown, capabilities?: {
    backend?: "stock-v6";
}): Readonly<{
    profile: ConsumerProfile;
    profileSha256: string;
    prepare(request: PrepareRequest, options?: RuntimeOptions): Promise<PreparedRequest>;
}>;
export {};
