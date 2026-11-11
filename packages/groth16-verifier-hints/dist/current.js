/** Current consumer boundary. Profiles are trusted application configuration;
 * host mismatch guards do not replace constrained key/statement authorization. */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { prepareRuntimeKey, prepareRuntimeHints68, } from "./index.js";
import { prepareFixedKey, prepareFixedHints68, } from "./fixed.js";
import { FR, integer, tuple } from "./parsers.js";
import { hash, prepareConstants } from "./internal/core.js";
import { constants } from "./internal/constants.js";
/** Stock Aztec v6.0.0 release (aztec-packages tag v6.0.0). */
const STOCK_AZTEC = "0219f11d8133970df3974fe5ae65e006bf8c193a";
const NOIR = "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7";
/** The only backend each execution mode may declare, with its exact Aztec source. */
const BACKENDS = {
    private: { backend: "stock-v6", aztecCommit: STOCK_AZTEC },
    offchain: { backend: "stock-v6", aztecCommit: STOCK_AZTEC },
};
function record(value, names, label) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error(`${label}: expected object`);
    const result = value;
    if (Object.keys(result).length !== names.length ||
        names.some((n) => !Object.hasOwn(result, n)) ||
        Object.keys(result).some((n) => !names.includes(n)))
        throw new Error(`${label}: unknown or missing property`);
    return result;
}
function decimal(value, label) {
    if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value))
        throw new Error(`${label}: canonical decimal required`);
    integer(value, FR, label);
    return value;
}
/** Validate and copy before hashing or invoking any arithmetic backend. */
export function parseProfile(value) {
    const p = record(value, [
        "schema",
        "name",
        "mode",
        "keyPolicy",
        "inputCount",
        "certificate",
        "keyHash",
        "configurationHash",
        "statementSchema",
        "toolchain",
        "domain",
    ], "profile");
    const t = record(p.toolchain, ["aztecCommit", "noirCommit", "backend"], "toolchain");
    if (p.schema !== "groth16-verifier-profile-v2" ||
        p.statementSchema !== "groth16-verifier-statement-v1" ||
        p.domain !== "finite-pairing-operands-v1")
        throw new Error("Unknown profile/statement/domain schema");
    if (typeof p.name !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(p.name))
        throw new Error("Invalid profile name");
    if (!["private", "offchain"].includes(p.mode))
        throw new Error("Unknown execution mode");
    if (!["fixed", "runtime"].includes(p.keyPolicy))
        throw new Error("Unknown key policy");
    if (!Number.isSafeInteger(p.inputCount) ||
        p.inputCount < 0 ||
        p.inputCount > 256)
        throw new Error("Unsupported input count");
    if (p.certificate !== `groth16-${p.keyPolicy}-global68-v1`)
        throw new Error("Certificate/profile mismatch");
    decimal(p.keyHash, "key hash");
    if (p.keyPolicy === "fixed")
        decimal(p.configurationHash, "configuration hash");
    else if (p.configurationHash !== null)
        throw new Error("Runtime profile cannot have fixed configuration hash");
    const expected = BACKENDS[p.mode];
    if (t.backend !== expected.backend)
        throw new Error("Incompatible backend declaration");
    if (t.aztecCommit !== expected.aztecCommit || t.noirCommit !== NOIR)
        throw new Error("Incompatible toolchain pins");
    return Object.freeze({
        ...p,
        toolchain: Object.freeze({ ...t }),
    });
}
function sorted(value) {
    if (Array.isArray(value))
        return value.map(sorted);
    if (value && typeof value === "object")
        return Object.fromEntries(Object.entries(value)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
            .map(([k, v]) => [k, sorted(v)]));
    return value;
}
export function profileHash(value) {
    return bytesToHex(sha256(new TextEncoder().encode(JSON.stringify(sorted(parseProfile(value))))));
}
const k = prepareConstants(constants);
/** Same Poseidon2 preimage as schema::statement_id<N>. Context binding does not
 * establish that the original Groth16 circuit authenticated that context. */
export function statementId(profile, application, publicInputs) {
    const p = parseProfile(profile);
    const app = tuple(application, 6, "application").map((v) => integer(v, FR, "application field"));
    const inputs = tuple(publicInputs, p.inputCount, "public inputs").map((v) => integer(v, FR, "public input"));
    return hash([
        0x4731365f52554e54494d455f563100n + 2n,
        BigInt(p.inputCount),
        BigInt(p.keyHash),
        ...app,
        ...inputs,
    ], k);
}
const packets = new WeakMap();
function freeze(v) {
    if (v && typeof v === "object") {
        for (const c of Object.values(v))
            freeze(c);
        Object.freeze(v);
    }
    return v;
}
/** Reject cross-profile packets, including structurally forged plain objects. */
export function assertPreparedRequest(profile, packet) {
    if (packets.get(packet) !== profileHash(profile))
        throw new Error("Prepared request/profile mismatch");
}
/** An optional backend declaration must match the profile's backend. */
export function createVerifier(profile, keyMaterial, capabilities = {}) {
    const p = parseProfile(profile), digest = profileHash(p);
    if (capabilities.backend !== undefined &&
        capabilities.backend !== p.toolchain.backend)
        throw new Error("Backend/profile mismatch");
    let fixed;
    let runtime;
    if (p.keyPolicy === "fixed") {
        const d = record(keyMaterial, ["schema", "verificationKey", "tPreimage"], "fixed descriptor");
        if (d.schema !== "groth16-fixed-key-v1")
            throw new Error("Current fixed descriptor schema required");
        fixed = prepareFixedKey({
            ...d,
            schema: "groth16-fixed-global66-v1",
        }, p.configurationHash);
    }
    else
        runtime = prepareRuntimeKey(keyMaterial);
    const prepared = fixed ?? runtime;
    if (prepared.inputCount !== p.inputCount)
        throw new Error("Key/profile input count mismatch");
    if (prepared.keyHash !== BigInt(p.keyHash))
        throw new Error("Key/profile authorization mismatch");
    return Object.freeze({
        profile: p,
        profileSha256: digest,
        async prepare(request, options = {}) {
            const application = tuple(request.application, 6, "application").map((v) => integer(v, FR, "application field"));
            const publicInputs = tuple(request.publicInputs, p.inputCount, "public inputs").map((v) => integer(v, FR, "public input"));
            const statement = statementId(p, application, publicInputs);
            const hints = fixed
                ? await prepareFixedHints68({ key: fixed, proof: request.proof, publicInputs }, options)
                : await prepareRuntimeHints68({ key: runtime, proof: request.proof, publicInputs, application }, options);
            const common = {
                statement,
                application,
                ...(p.inputCount === 0 ? {} : { public_inputs: publicInputs }),
            };
            const callArguments = "raw" in hints
                ? { ...common, raw: hints.raw }
                : { ...common, key: hints.flatKey, proof: hints.proof };
            const producerInputs = "raw" in hints
                ? {
                    statement,
                    application,
                    ...(p.inputCount === 0 ? {} : { inputs: publicInputs }),
                    raw: hints.raw,
                    residue: hints.residue,
                    ...(p.inputCount === 0
                        ? {}
                        : { glv_components: hints.glvComponents }),
                    accumulators: hints.accumulators,
                    quotient: hints.quotient,
                    block_residuals: hints.blockResiduals,
                }
                : p.inputCount === 0
                    ? Object.fromEntries(Object.entries(hints.producer).filter(([name]) => !["inputs", "magnitudes", "negative"].includes(name)))
                    : hints.producer;
            // The generated ABI keeps all pairing witnesses in the common capsule, so
            // the fixed-key residue is prepended to it here.
            const capsules = p.mode === "offchain"
                ? []
                : hints.capsules[p.mode]
                    .map((c, i, all) => "raw" in hints && i === all.length - 1
                    ? { ...c, values: [...hints.residue.flat(), ...c.values] }
                    : c)
                    .filter((c) => c.values.length !== 0);
            const packet = freeze({
                profileSha256: digest,
                statement,
                application,
                publicInputs,
                hints,
                capsules,
                callArguments,
                producerInputs,
            });
            packets.set(packet, digest);
            return packet;
        },
    });
}
