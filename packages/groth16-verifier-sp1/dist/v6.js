import { sha256 } from "@noble/hashes/sha256";
import { prepareFixedKey, prepareFixedHints68, } from "groth16-verifier-hints/fixed";
import { descriptorV6 } from "./config-v6.js";
import { FQ, FR, parseProof } from "groth16-verifier-hints";
// SP1 v6 adapter for the Noir entry point sp1::v6::verify: SP1 circuit version
// v6.1.0, the Groth16 key of SP1 v6.1.0 through v6.10.0.
/** The SP1 circuit version whose Groth16 key and root this adapter pins. */
export const SP1_V6_CIRCUIT_VERSION = "v6.1.0";
/** First four bytes of sha256(groth16_vk.bin): the proof's verifier selector. */
export const SP1_V6_VERIFIER_SELECTOR = "4388a21c";
/** The recursion verification-key root SP1 circuit version v6.1.0 pins (public input 3). */
export const SP1_V6_VK_ROOT = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352n;
// Configuration hash of the SP1 v6 descriptor (config-v6.js). Like
// SP1_CONFIGURATION_HASH it detects only a mismatch between that descriptor and
// this constant; scripts/tests/test_sp1_key.py checks the descriptor against
// the saved upstream key.
export const SP1_V6_CONFIGURATION_HASH = 15487858104255947845364280229307291878380969494329548901005093093132018200728n;
const PROOF_BYTES = 356;
// The twist coefficient 3 / (9 + i) of BN254's G2 curve y^2 = x^3 + b'.
const TWIST_B = [
    19485874751759354771024239261021720505790618469301721065564631296452457478373n,
    266929791119991161246907387137283842545076965332900288569378510910307636690n,
];
const fq2Mul = (a, b) => [
    (((a[0] * b[0] - a[1] * b[1]) % FQ) + FQ) % FQ,
    (a[0] * b[1] + a[1] * b[0]) % FQ,
];
/** Finite and on y^2 = x^3 + 3. */
function onG1(x, y) {
    return !(x === 0n && y === 0n) && (y * y - x * x * x - 3n) % FQ === 0n;
}
/** Finite and on the twist y^2 = x^3 + 3 / (9 + i); pairs are (real, imaginary). */
function onTwist(x, y) {
    if (x.concat(y).every((v) => v === 0n))
        return false;
    const rhs = fq2Mul(fq2Mul(x, x), x), lhs = fq2Mul(y, y);
    return lhs[0] === (rhs[0] + TWIST_B[0]) % FQ && lhs[1] === (rhs[1] + TWIST_B[1]) % FQ;
}
export function prepareSp1V6Key() {
    return prepareFixedKey(descriptorV6, SP1_V6_CONFIGURATION_HASH);
}
let cachedKey;
function bytes(value, label) {
    if (!(value instanceof Uint8Array) && !Array.isArray(value))
        throw new Error(`${label} must be bytes`);
    if (Array.from(value).some((v) => !Number.isInteger(v) || v < 0 || v > 255))
        throw new Error(`${label} must be bytes`);
    return Uint8Array.from(value);
}
function field(value, label) {
    if (typeof value !== "bigint" &&
        (typeof value !== "string" ||
            !/^(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value)))
        throw new Error(`${label}: expected unsigned decimal/hex string or bigint`);
    const result = BigInt(value);
    if (result < 0n || result >= FR)
        throw new Error(`${label}: noncanonical integer`);
    return result;
}
function word(data, index) {
    let x = 0n;
    for (const b of data.subarray(4 + 32 * index, 36 + 32 * index))
        x = (x << 8n) + BigInt(b);
    return x;
}
/**
 * Parse SP1 v6 Groth16 proof bytes (`SP1ProofWithPublicValues::bytes()`): the
 * selector, exit code, vk root and nonce words, then A, B, C as eight words.
 * Rejects what SP1's onchain verifier rejects before the pairing: another
 * selector, a nonzero exit code, another vk root and a noncanonical nonce; and
 * A, B, C that are noncanonical, at infinity or off their curves (G2 subgroup
 * membership is left to the verifier).
 */
export function parseSp1V6ProofBytes(value) {
    let data;
    if (typeof value === "string") {
        if (!new RegExp(`^0x[0-9a-fA-F]{${2 * PROOF_BYTES}}$`).test(value))
            throw new Error(`SP1 v6 proof must be exactly ${PROOF_BYTES} bytes`);
        data = Uint8Array.from(value
            .slice(2)
            .match(/../g)
            .map((x) => parseInt(x, 16)));
    }
    else if (value instanceof Uint8Array && value.length === PROOF_BYTES)
        data = Uint8Array.from(value);
    else
        throw new Error(`SP1 v6 proof must be exactly ${PROOF_BYTES} bytes`);
    const selector = Array.from(data.subarray(0, 4), (x) => x.toString(16).padStart(2, "0")).join("");
    if (selector !== SP1_V6_VERIFIER_SELECTOR)
        throw new Error("SP1 v6 proof verifier selector mismatch");
    const [exitCode, vkRoot, nonce] = [0, 1, 2].map((i) => word(data, i));
    if (exitCode !== 0n)
        throw new Error("SP1 v6 proof has a nonzero exit code");
    if (vkRoot !== SP1_V6_VK_ROOT)
        throw new Error("SP1 v6 proof vk root mismatch");
    if (nonce >= FR)
        throw new Error("SP1 v6 proof nonce: noncanonical integer");
    const p = Array.from({ length: 8 }, (_, i) => word(data, 3 + i));
    if (p.some((x) => x >= FQ))
        throw new Error("SP1 v6 proof: noncanonical coordinate");
    if (!onG1(p[0], p[1]))
        throw new Error("SP1 v6 proof: A is infinity or not on the curve");
    if (!onTwist([p[3], p[2]], [p[5], p[4]]))
        throw new Error("SP1 v6 proof: B is infinity or not on the twist");
    if (!onG1(p[6], p[7]))
        throw new Error("SP1 v6 proof: C is infinity or not on the curve");
    // SP1's Ethereum encoding orders each Fq2 coefficient pair imaginary first.
    const proof = parseProof({
        protocol: "groth16",
        curve: "bn128",
        pi_a: [p[0], p[1]],
        pi_b: [
            [p[3], p[2]],
            [p[5], p[4]],
        ],
        pi_c: [p[6], p[7]],
    });
    return Object.freeze({ proof, exitCode, vkRoot, nonce });
}
/**
 * The five public inputs SP1's v6 onchain verifier passes to the Groth16 check:
 * [program vkey, SHA256(public values) & (2^253-1), 0, SP1_V6_VK_ROOT, nonce].
 */
export function sp1V6PublicInputs(vkey, publicValues, nonce) {
    const programKey = field(vkey, "SP1 program vkey"), proofNonce = field(nonce, "SP1 proof nonce"), digest = sha256(bytes(publicValues, "SP1 public values"));
    digest[0] &= 31;
    let scalar = 0n;
    for (const b of digest)
        scalar = (scalar << 8n) + BigInt(b);
    return Object.freeze([programKey, scalar, 0n, SP1_V6_VK_ROOT, proofNonce]);
}
/**
 * Hints for sp1::v6::verify. `arguments` holds every argument of that function,
 * by parameter name, in order; pass it through `toNoirInput`.
 */
export async function prepareSp1V6Hints(request, options = {}) {
    const key = request.key ?? (cachedKey ??= prepareSp1V6Key());
    if (key.configurationHash !== SP1_V6_CONFIGURATION_HASH || key.inputCount !== 5)
        throw new Error("SP1 v6 adapter requires the pinned SP1 v6 configuration");
    const { proof, nonce } = parseSp1V6ProofBytes(request.proof);
    const values = bytes(request.publicValues, "SP1 public values");
    const publicInputs = sp1V6PublicInputs(request.vkey, values, nonce);
    const hints = await prepareFixedHints68({ key, proof, publicInputs }, options);
    const args = Object.freeze({
        program_vkey: publicInputs[0],
        public_values: Object.freeze(Array.from(values)),
        proof_nonce: nonce,
        raw: hints.raw,
        residue: hints.residue,
        components: hints.glvComponents,
        accumulators: hints.accumulators,
        quotient: hints.quotient,
        block_residuals: hints.blockResiduals,
    });
    return Object.freeze({ ...hints, arguments: args });
}
