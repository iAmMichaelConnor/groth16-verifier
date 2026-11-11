import {
  RUNTIME_66,
  RUNTIME_67,
  RUNTIME_68,
  type CertificateSchema,
} from "./schemas.js";
import { constants } from "./internal/constants.js";
import {
  prepareConstants,
  prepareKey,
  prepareRequest,
  generateKernel,
  generateKernel67,
  generateKernel68,
  hash,
  dense,
  encoded,
  coords1,
  coords2,
  checkResiduePreflight,
} from "./internal/core.js";
import {
  FR,
  FQ,
  integer,
  tuple,
  parseVerificationKey,
  parseProof,
  type Integer,
} from "./parsers.js";
import { decomposeScalar } from "./glv.js";
import type { PreparedKernel } from "./wasm.js";
export { parseVerificationKey, parseProof, FR, FQ, decomposeScalar };
export type { Integer, VerificationKey, Proof } from "./parsers.js";
export type { PreparedKernel } from "./wasm.js";
export type Limb = readonly [bigint, bigint, bigint];
export type RawG1 = readonly [Limb, Limb];
export interface RawVerificationKey {
  readonly alpha: RawG1;
  readonly beta: readonly Limb[];
  readonly gamma: readonly Limb[];
  readonly delta: readonly Limb[];
  readonly ic: readonly RawG1[];
}
const DOMAIN = 0x4731365f52554e54494d455f563100n;
export const CAPSULE_BASE = RUNTIME_66.capsuleBase;
const k = prepareConstants(constants);
declare const preparedBrand: unique symbol;
export interface PreparedKey {
  readonly inputCount: number;
  readonly keyHash: bigint;
  readonly [preparedBrand]: true;
}
// Internal points and caches are never returned, even as readonly TypeScript values.
const keys = new WeakMap<PreparedKey, ReturnType<typeof prepareKey>>();
const freeze = <T>(value: T): Readonly<T> => {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};
export function prepareRuntimeKey(value: unknown): PreparedKey {
  const parsed = parseVerificationKey(value),
    internal = prepareKey(parsed, k);
  const handle = Object.freeze({
    inputCount: parsed.nPublic,
    keyHash: internal.keyHash,
  }) as PreparedKey;
  keys.set(handle, internal);
  return handle;
}
export interface PairingHints {
  readonly residue: readonly Limb[];
  readonly accumulators: readonly (readonly Limb[])[];
  readonly quotient: readonly Limb[];
  readonly block_residuals: readonly Limb[];
}
export interface Capsule {
  readonly scope: bigint;
  readonly slot: bigint;
  readonly values: readonly bigint[];
}
export interface RuntimeHints {
  readonly inputCount: number;
  readonly keyHash: bigint;
  readonly statement: bigint;
  readonly application: readonly bigint[];
  readonly key: RawVerificationKey;
  readonly flatKey: readonly Limb[];
  readonly publicInputs: readonly bigint[];
  readonly proof: readonly Limb[];
  readonly claimedL: RawG1;
  readonly magnitudes: readonly (readonly bigint[])[];
  readonly negative: readonly (readonly boolean[])[];
  readonly pairing: PairingHints;
  readonly capsules: {
    readonly private: readonly Capsule[];
  };
  readonly producer: Readonly<Record<string, unknown>>;
}
function fqLimbs(x: bigint): Limb {
  return [
    x & ((1n << 120n) - 1n),
    (x >> 120n) & ((1n << 120n) - 1n),
    x >> 240n,
  ];
}
function fromLimbs(x: readonly bigint[]): bigint {
  return x[0] + (x[1] << 120n) + (x[2] << 240n);
}
function requestBytes(
  raw: readonly (readonly bigint[])[],
  context: readonly bigint[],
): Uint8Array {
  const out = new Uint8Array(864);
  [...raw.map(fromLimbs), ...context].forEach((x, i) => {
    for (let j = 31; j >= 0; j--) {
      out[i * 32 + j] = Number(x & 255n);
      x >>= 8n;
    }
  });
  return out;
}
function decodeKernel(
  bytes: Uint8Array,
  schema: CertificateSchema,
): PairingHints {
  const words = schema.outputBytes / 32;
  if (!(bytes instanceof Uint8Array) || bytes.length !== schema.outputBytes)
    throw new Error(`Kernel response must be ${schema.outputBytes} bytes`);
  const values: bigint[] = [];
  for (let i = 0; i < words; i++) {
    let v = 0n;
    for (const b of bytes.subarray(i * 32, (i + 1) * 32))
      v = (v << 8n) + BigInt(b);
    if (v >= (i < words - 2 ? FQ : FR))
      throw new Error("Kernel returned noncanonical field element");
    values.push(v);
  }
  // normalized Miller value [0..12) and diagnostic rho/z are not Noir witnesses.
  let offset = 12;
  const take = (n: number) => {
    const a = values.slice(offset, offset + n).map(fqLimbs);
    offset += n;
    return a;
  };
  return {
    residue: take(36),
    accumulators: Array.from({ length: schema.accumulators }, () => take(12)),
    quotient: take(schema.quotient),
    block_residuals: take(9),
  };
}
// Shape/inverse/subfield/aggregate preflight only, NOT a complete pairing verifier.
// An arbitrary injected kernel can still forge intermediate relations; Noir must check them.
function validatePairing(
  p: PairingHints,
  raw: readonly Limb[],
  context: readonly bigint[],
  schema: CertificateSchema,
): void {
  const coefficients = [
    ...p.residue,
    ...p.accumulators.flat(),
    ...p.quotient,
    ...p.block_residuals,
  ];
  if (
    p.residue.length !== 36 ||
    p.accumulators.length !== schema.accumulators ||
    p.accumulators.some((a) => a.length !== 12) ||
    p.quotient.length !== schema.quotient ||
    p.block_residuals.length !== 9
  )
    throw new Error("Kernel witness shape");
  for (const a of coefficients) {
    if (
      a.length !== 3 ||
      a.some(
        (x, i) =>
          typeof x !== "bigint" ||
          x < 0n ||
          x >= 1n << BigInt(i < 2 ? 120 : 14),
      ) ||
      fromLimbs(a) >= FQ
    )
      throw new Error("Kernel witness encoding");
  }
  checkResiduePreflight(p.residue.map(fromLimbs));
  const rho = hash(
    [
      schema.domain,
      BigInt(schema.identities),
      ...context,
      ...dense([...raw, ...p.residue, ...p.accumulators.flat()]),
    ],
    k,
  );
  if (rho === 0n) throw new Error("Zero transcript challenge");
  const z = hash([schema.domain + 1n, rho, ...dense(p.quotient)], k);
  const mod = (v: bigint) => ((v % FQ) + FQ) % FQ;
  const ev = p.quotient.reduceRight((v, x) => mod(v * z + fromLimbs(x)), 0n);
  let sum = 0n,
    power = 1n;
  const step = mod(rho ** 8n);
  for (const b of p.block_residuals) {
    sum = mod(sum + power * fromLimbs(b));
    power = mod(power * step);
  }
  if (mod(ev * mod(z ** 12n - 18n * z ** 6n + 82n) - sum) !== 0n)
    throw new Error("Kernel aggregate relation mismatch");
}
/** Complete runtime-key preparation. Outputs remain untrusted witnesses checked by Noir. */
async function prepareRuntime(
  request: {
    key: PreparedKey;
    proof: unknown;
    publicInputs: readonly Integer[];
    application: readonly Integer[];
  },
  options: {
    kernel?: PreparedKernel;
  },
  schema: CertificateSchema,
): Promise<RuntimeHints> {
  const key = keys.get(request.key);
  if (!key) throw new Error("Unknown prepared key; call prepareRuntimeKey");
  const scalars = tuple(request.publicInputs, key.n, "public inputs").map((x) =>
    integer(x, FR, "public input"),
  );
  const application = tuple(request.application, 6, "application").map((x) =>
    integer(x, FR, "application field"),
  );
  const proof = parseProof(request.proof);
  // This stage performs G1/G2 membership, finite L, and the public-input MSM.
  const prepared = prepareRequest(proof, scalars, key, k);
  const raw = prepared.raw as Limb[];
  const pairing: PairingHints = options.kernel
    ? decodeKernel(
        await options.kernel(requestBytes(raw, prepared.context)),
        schema,
      )
    : (schema === RUNTIME_68
        ? generateKernel68
        : schema === RUNTIME_67
          ? generateKernel67
          : generateKernel)(prepared, k).data;
  validatePairing(pairing, raw, prepared.context, schema);
  const glv = scalars.map(decomposeScalar),
    magnitudes = glv.map((v) => v.magnitudes),
    negative = glv.map((v) => v.negative);
  const flatKey = encoded([
    ...coords1(key.alpha),
    ...coords2(key.beta),
    ...coords2(key.gamma),
    ...coords2(key.delta),
    ...key.ic.flatMap(coords1),
  ]) as Limb[];
  const rawKey: RawVerificationKey = {
    alpha: flatKey.slice(0, 2) as unknown as RawG1,
    beta: flatKey.slice(2, 6),
    gamma: flatKey.slice(6, 10),
    delta: flatKey.slice(10, 14),
    ic: key.ic.map(
      (_: unknown, i: number) =>
        flatKey.slice(14 + 2 * i, 16 + 2 * i) as unknown as RawG1,
    ),
  };
  const claimedL = raw.slice(8, 10) as unknown as RawG1,
    rawProof = raw.slice(0, 8);
  const statement = hash(
    [DOMAIN + 2n, BigInt(key.n), key.keyHash, ...application, ...scalars],
    k,
  );
  const common: Capsule = {
    scope: 0n,
    slot: schema.capsuleBase + 1n,
    values: [
      ...pairing.residue.flat(),
      ...pairing.accumulators.flat(2),
      ...pairing.quotient.flat(),
      ...pairing.block_residuals.flat(),
    ],
  };
  const privateCapsule: Capsule = {
    scope: 0n,
    slot: schema.capsuleBase,
    values: [
      ...claimedL.flat(),
      ...magnitudes.flat(),
      ...negative.flat().map((v) => (v ? 1n : 0n)),
    ],
  };
  const pairingOnly = {
    residue: pairing.residue,
    accumulators: pairing.accumulators,
    quotient: pairing.quotient,
    block_residuals: pairing.block_residuals,
  };
  const producer = {
    statement,
    application,
    key: rawKey,
    inputs: scalars,
    proof: rawProof,
    claimed_l: claimedL,
    magnitudes,
    negative,
    ...pairingOnly,
  };
  return freeze({
    inputCount: key.n,
    keyHash: key.keyHash,
    statement,
    application,
    key: rawKey,
    flatKey,
    publicInputs: scalars,
    proof: rawProof,
    claimedL,
    magnitudes,
    negative,
    pairing: pairingOnly,
    capsules: {
      private: [privateCapsule, common],
    },
    producer,
  });
}
export type RuntimeRequest = Parameters<typeof prepareRuntime>[0];
export type RuntimeOptions = Parameters<typeof prepareRuntime>[1];
export function prepareRuntimeHints(
  request: RuntimeRequest,
  options: RuntimeOptions = {},
): Promise<RuntimeHints> {
  return prepareRuntime(request, options, RUNTIME_66);
}
export async function prepareRuntimeHints67(
  request: RuntimeRequest,
  options: RuntimeOptions = {},
) {
  const hints = await prepareRuntime(request, options, RUNTIME_67);
  return freeze({ ...hints, schema: "groth16-runtime-global67-v1" as const });
}
export const PREFIX_CAPSULE_BASE = RUNTIME_67.capsuleBase;
export async function prepareRuntimeHints68(
  request: RuntimeRequest,
  options: RuntimeOptions = {},
) {
  const hints = await prepareRuntime(request, options, RUNTIME_68);
  return freeze({ ...hints, schema: "groth16-runtime-global68-v1" as const });
}
export const TAIL_CAPSULE_BASE = RUNTIME_68.capsuleBase;

/** Check concrete contract arity explicitly. The supplied examples currently use N=1. */
export function privateCallArguments(
  hints: RuntimeHints,
  expectedInputCount: number,
) {
  if (
    !Number.isSafeInteger(expectedInputCount) ||
    expectedInputCount !== hints.inputCount
  )
    throw new Error("Contract input count mismatch");
  return {
    key: hints.flatKey,
    public_inputs: hints.publicInputs,
    proof: hints.proof,
  };
}
/** Lossless JSON-compatible data for Noir input tooling. BigInts become decimal strings. */
export function toNoirInput(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(toNoirInput);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, v]) => [key, toNoirInput(v)]),
    );
  if (
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number" ||
    value === null
  )
    return value;
  throw new Error("Unsupported Noir input value");
}
