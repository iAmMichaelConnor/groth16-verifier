import { type PreparedRequest } from "./current.js";
declare const TARGET: {
    verifierTarget: "noir-recursive";
};
export interface ArtifactIdentity {
    readonly role: "producer" | "private-consumer";
    readonly artifactSha256: string;
    readonly bytecodeSha256: string;
    readonly verificationKeySha256: string | null;
}
export interface ArtifactManifest {
    readonly schema: "groth16-verifier-artifacts-v1";
    readonly profileSha256: string;
    readonly artifacts: readonly ArtifactIdentity[];
}
export interface ProofData {
    proof: Uint8Array;
    publicInputs: string[];
}
/** Directly implemented by the pinned UltraHonkBackend. Reuse the application's
 * Barretenberg instance when constructing it; do not instantiate one per call. */
export interface ProducerBackend {
    getVerificationKey(options: typeof TARGET): Promise<Uint8Array>;
    generateProof(witness: Uint8Array, options: typeof TARGET): Promise<ProofData>;
    verifyProof(data: ProofData, options: typeof TARGET): Promise<boolean>;
}
export interface ProducerExecutor {
    execute(inputs: Record<string, unknown>): Promise<{
        witness: Uint8Array;
    }>;
}
export interface ProducerCertificate {
    readonly profileSha256: string;
    readonly statement: bigint;
    readonly producerKeyHash: bigint;
    readonly producerKey: readonly bigint[];
    readonly proof: readonly bigint[];
}
/** Strict big-endian canonical Fr decoding. Proof arrays already include BB's
 * eight DefaultIO accumulator fields; only the user statement is supplied apart. */
export declare function decodeFields(bytes: Uint8Array, count: number): bigint[];
export declare function assertProducerCertificate(profile: unknown, packet: PreparedRequest, certificate: ProducerCertificate): void;
/** Authenticate source bytes before the caller constructs NoirJS and BB objects.
 * Factories receive this exact parsed artifact/bytecode; they must be trusted code. */
export declare function createProducer(options: {
    profile: unknown;
    artifactBytes: Uint8Array;
    manifest: ArtifactManifest;
    executor: (artifact: Readonly<Record<string, unknown>>) => ProducerExecutor | Promise<ProducerExecutor>;
    backend: (bytecode: string) => ProducerBackend | Promise<ProducerBackend>;
}): Promise<Readonly<{
    producerKey: readonly bigint[];
    producerKeyHash: bigint;
    prove(packet: PreparedRequest): Promise<ProducerCertificate>;
}>>;
export {};
