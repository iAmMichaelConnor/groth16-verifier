import { sha256 } from "@noble/hashes/sha256";
import { prepareFixedKey, prepareFixedHints, prepareFixedHints67, prepareFixedHints68, } from "groth16-verifier-hints/fixed";
import { descriptor } from "./config.js";
import { poseidon2Hash } from "groth16-verifier-hints/transcript";
import { FR, parseProof } from "groth16-verifier-hints";
function integer(value, modulus, label) {
    if (typeof value !== "bigint" &&
        (typeof value !== "string" ||
            !/^(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value)))
        throw new Error(`${label}: expected unsigned decimal/hex string or bigint`);
    const result = BigInt(value);
    if (result < 0n || result >= modulus)
        throw new Error(`${label}: noncanonical integer`);
    return result;
}
function tuple(value, length, label) {
    if (!Array.isArray(value) || value.length !== length)
        throw new Error(`${label}: expected ${length} values`);
    return value;
}
// Configuration hash of the current compiled SP1 fixed-key provider. It is computed
// from the in-package descriptor (config.js), so it detects only a
// mismatch between that descriptor and this constant. It does not anchor the
// descriptor or the Noir constants to upstream SP1 v5, and it is not an application
// approval. scripts/tests/test_sp1_key.py independently decodes the
// retained upstream SP1 v5 key and compares the complete descriptor and preimage.
export const SP1_CONFIGURATION_HASH = 11610070592383739928887964744989344216464605173011498513140240201529586530148n;
let cachedKey;
export function prepareSp1Key() {
    return prepareFixedKey(descriptor, SP1_CONFIGURATION_HASH);
}
function values32(values) {
    if (!(values instanceof Uint8Array) && !Array.isArray(values))
        throw new Error("SP1 public values must be bytes");
    if (values.length !== 32 ||
        Array.from(values).some((v) => !Number.isInteger(v) || v < 0 || v > 255))
        throw new Error("SP1 adapter requires exactly 32 bytes");
    return Uint8Array.from(values);
}
/** Exact pinned SP1 v5 proof selector; other verifier revisions require their own configuration. */
export const SP1_VERIFIER_SELECTOR = "a4594c59";
export function parseSp1ProofBytes(value) {
    let bytes;
    if (typeof value === "string") {
        if (!/^0x[0-9a-fA-F]{520}$/.test(value))
            throw new Error("SP1 proof must be exactly 260 bytes");
        bytes = Uint8Array.from(value
            .slice(2)
            .match(/../g)
            .map((x) => parseInt(x, 16)));
    }
    else if (value instanceof Uint8Array && value.length === 260)
        bytes = Uint8Array.from(value);
    else
        throw new Error("SP1 proof must be exactly 260 bytes");
    const selector = Array.from(bytes.slice(0, 4), (x) => x.toString(16).padStart(2, "0")).join("");
    if (selector !== SP1_VERIFIER_SELECTOR)
        throw new Error("SP1 proof verifier selector mismatch");
    const fields = Array.from({ length: 8 }, (_, i) => {
        let x = 0n;
        for (const b of bytes.slice(4 + 32 * i, 36 + 32 * i))
            x = (x << 8n) + BigInt(b);
        return x;
    });
    // SP1's Ethereum wire encoding reverses the two Fq2 coefficients.
    return parseProof({
        protocol: "groth16",
        curve: "bn128",
        pi_a: [fields[0], fields[1]],
        pi_b: [
            [fields[3], fields[2]],
            [fields[5], fields[4]],
        ],
        pi_c: [fields[6], fields[7]],
    });
}
/** SP1-specific convention: [program vkey, SHA256(public values) masked to 253 bits]. */
export function sp1PublicInputs(vkey, publicValues) {
    const programKey = integer(vkey, FR, "SP1 program vkey"), digest = sha256(values32(publicValues));
    digest[0] &= 31;
    let scalar = 0n;
    for (const b of digest)
        scalar = (scalar << 8n) + BigInt(b);
    return Object.freeze([programKey, scalar]);
}
/**
 * Fixed-SP1 private-call arguments, capsules and the offchain producer inputs.
 * `statement` = Poseidon2("GR16_SINGLE_V6\x01", application[6], vkey,
 * publicValues[32]) is an SP1-specific statement schema. No Noir circuit in this
 * repository computes it; treat it as unauthenticated host
 * metadata unless a consumer circuit recomputes it with this exact layout.
 */
async function prepareSp1(request, options, format) {
    const key = request.key ?? (cachedKey ??= prepareSp1Key());
    if (key.configurationHash !== SP1_CONFIGURATION_HASH || key.inputCount !== 2)
        throw new Error("SP1 adapter requires the pinned SP1 configuration");
    const values = Object.freeze(Array.from(values32(request.publicValues))), inputs = sp1PublicInputs(request.vkey, values);
    const application = Object.freeze(tuple(request.application, 6, "SP1 application").map((x) => integer(x, FR, "application field")));
    const proof = typeof request.proof === "string" || request.proof instanceof Uint8Array
        ? parseSp1ProofBytes(request.proof)
        : request.proof;
    const hints = await (format === 68
        ? prepareFixedHints68
        : format === 67
            ? prepareFixedHints67
            : prepareFixedHints)({ key, proof, publicInputs: inputs }, options);
    const statement = poseidon2Hash([
        0x475231365f53494e474c455f563601n,
        ...application,
        inputs[0],
        ...values.map(BigInt),
    ]);
    const args = Object.freeze({
        raw: hints.raw,
        residue: hints.residue,
        vkey: inputs[0],
        public_values: values,
    });
    const producer = Object.freeze({
        statement,
        application,
        ...args,
        glv_components: hints.glvComponents,
        accumulators: hints.accumulators,
        quotient: hints.quotient,
        block_residuals: hints.blockResiduals,
    });
    return Object.freeze({
        ...hints,
        statement,
        application,
        arguments: args,
        producer,
    });
}
export function prepareSp1Hints(request, options = {}) {
    return prepareSp1(request, options, 66);
}
export async function prepareSp1Hints67(request, options = {}) {
    const hints = await prepareSp1(request, options, 67);
    return Object.freeze({
        ...hints,
        schema: "groth16-fixed-global67-v1",
    });
}
export async function prepareSp1Hints68(request, options = {}) {
    const hints = await prepareSp1(request, options, 68);
    return Object.freeze({
        ...hints,
        schema: "groth16-fixed-global68-v1",
    });
}
export * from "./v6.js";
