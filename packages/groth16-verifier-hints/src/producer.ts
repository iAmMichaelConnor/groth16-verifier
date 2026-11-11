/** Optional O orchestration over caller-owned NoirJS/BB instances. No downloads,
 * backend construction, or proving happen until the corresponding explicit call. */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import {
  assertPreparedRequest,
  parseProfile,
  profileHash,
  type PreparedRequest,
} from "./current.js";
import { toNoirInput } from "./index.js";
import { FR, integer } from "./parsers.js";
import { hash, prepareConstants } from "./internal/core.js";
import { constants } from "./internal/constants.js";
const TARGET = { verifierTarget: "noir-recursive" as const };
const digest = (bytes: Uint8Array) => bytesToHex(sha256(bytes));
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
  generateProof(
    witness: Uint8Array,
    options: typeof TARGET,
  ): Promise<ProofData>;
  verifyProof(data: ProofData, options: typeof TARGET): Promise<boolean>;
}
export interface ProducerExecutor {
  execute(inputs: Record<string, unknown>): Promise<{ witness: Uint8Array }>;
}
export interface ProducerCertificate {
  readonly profileSha256: string;
  readonly statement: bigint;
  readonly producerKeyHash: bigint;
  readonly producerKey: readonly bigint[];
  readonly proof: readonly bigint[];
}
const issued = new WeakMap<ProducerCertificate, string>();
const k = prepareConstants(constants);
function exact(
  value: unknown,
  names: string[],
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label}: expected object`);
  const v = value as Record<string, unknown>;
  if (
    Object.keys(v).length !== names.length ||
    names.some((n) => !Object.hasOwn(v, n))
  )
    throw new Error(`${label}: unknown or missing property`);
  return v;
}
const isDigest = (v: unknown): v is string =>
  typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
function producerIdentity(
  profile: unknown,
  manifest: ArtifactManifest,
): ArtifactIdentity {
  exact(
    manifest,
    ["schema", "profileSha256", "artifacts"],
    "artifact manifest",
  );
  if (
    manifest.schema !== "groth16-verifier-artifacts-v1" ||
    manifest.profileSha256 !== profileHash(profile)
  )
    throw new Error("Artifact/profile mismatch");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 2)
    throw new Error("O requires producer and consumer artifacts");
  for (const a of manifest.artifacts) {
    exact(
      a,
      ["role", "artifactSha256", "bytecodeSha256", "verificationKeySha256"],
      "artifact identity",
    );
    if (
      !["producer", "private-consumer"].includes(a.role) ||
      !isDigest(a.artifactSha256) ||
      !isDigest(a.bytecodeSha256) ||
      (a.verificationKeySha256 !== null && !isDigest(a.verificationKeySha256))
    )
      throw new Error("Malformed artifact identity");
  }
  const producers = manifest.artifacts.filter((a) => a.role === "producer");
  if (
    producers.length !== 1 ||
    manifest.artifacts.filter((a) => a.role === "private-consumer").length !== 1
  )
    throw new Error("Duplicate artifact roles");
  if (producers[0].verificationKeySha256 === null)
    throw new Error("Approve the derived producer key before proving");
  return { ...producers[0] };
}
/** Strict big-endian canonical Fr decoding. Proof arrays already include BB's
 * eight DefaultIO accumulator fields; only the user statement is supplied apart. */
export function decodeFields(bytes: Uint8Array, count: number): bigint[] {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32 * count)
    throw new Error(`Expected ${count} field words`);
  return Array.from({ length: count }, (_, i) =>
    integer(
      "0x" + bytesToHex(bytes.subarray(i * 32, (i + 1) * 32)),
      FR,
      "backend field",
    ),
  );
}
function decodeBase64(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    !value.length ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  )
    throw new Error("Invalid artifact bytecode");
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
export function assertProducerCertificate(
  profile: unknown,
  packet: PreparedRequest,
  certificate: ProducerCertificate,
): void {
  assertPreparedRequest(profile, packet);
  if (
    issued.get(certificate) !== packet.profileSha256 ||
    certificate.statement !== packet.statement
  )
    throw new Error("Certificate/request mismatch");
}
/** Authenticate source bytes before the caller constructs NoirJS and BB objects.
 * Factories receive this exact parsed artifact/bytecode; they must be trusted code. */
export async function createProducer(options: {
  profile: unknown;
  artifactBytes: Uint8Array;
  manifest: ArtifactManifest;
  executor: (
    artifact: Readonly<Record<string, unknown>>,
  ) => ProducerExecutor | Promise<ProducerExecutor>;
  backend: (bytecode: string) => ProducerBackend | Promise<ProducerBackend>;
}) {
  const profile = parseProfile(options.profile);
  if (profile.mode !== "offchain")
    throw new Error("Producer requires offchain profile");
  const identity = producerIdentity(profile, options.manifest);
  const bytes = options.artifactBytes.slice();
  if (digest(bytes) !== identity.artifactSha256)
    throw new Error("Producer artifact digest mismatch");
  const artifact = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(bytes),
  );
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact))
    throw new Error("Expected compiled Noir artifact");
  if (digest(decodeBase64(artifact.bytecode)) !== identity.bytecodeSha256)
    throw new Error("Producer bytecode digest mismatch");
  const backend = await options.backend(artifact.bytecode);
  // Deriving a key is distinct from proving; compare it before witness execution.
  const keyBytes = (await backend.getVerificationKey(TARGET)).slice();
  if (digest(keyBytes) !== identity.verificationKeySha256)
    throw new Error("Producer verification key digest mismatch");
  const producerKey = Object.freeze(decodeFields(keyBytes, 115));
  if (producerKey[1] !== 9n)
    throw new Error(
      "Producer must expose one statement plus eight DefaultIO fields",
    );
  const producerKeyHash = hash(producerKey, k);
  if (producerKeyHash === 0n) throw new Error("Zero producer key hash");
  const executor = await options.executor(Object.freeze(artifact));
  return Object.freeze({
    producerKey,
    producerKeyHash,
    async prove(packet: PreparedRequest): Promise<ProducerCertificate> {
      assertPreparedRequest(profile, packet);
      const result = await executor.execute(
        toNoirInput(packet.producerInputs) as Record<string, unknown>,
      );
      const data = await backend.generateProof(result.witness, TARGET);
      if (
        !Array.isArray(data.publicInputs) ||
        data.publicInputs.length !== 1 ||
        integer(data.publicInputs[0], FR, "producer statement") !==
          packet.statement
      )
        throw new Error("Producer public statement mismatch");
      const proof = Object.freeze(decodeFields(data.proof, 458));
      if (!(await backend.verifyProof(data, TARGET)))
        throw new Error("Producer proof failed local verification");
      const certificate = Object.freeze({
        profileSha256: packet.profileSha256,
        statement: packet.statement,
        producerKeyHash,
        producerKey,
        proof,
      });
      issued.set(certificate, packet.profileSha256);
      return certificate;
    },
  });
}
