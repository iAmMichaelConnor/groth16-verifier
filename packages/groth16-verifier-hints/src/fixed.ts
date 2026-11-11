import {
  FIXED_66,
  FIXED_67,
  FIXED_68,
  type CertificateSchema,
} from "./schemas.js";
import { constants } from "./internal/constants.js";
import {
  prepareConstants,
  prepareKey,
  prepareRequest,
  prepareFixedContext,
  generateFixedKernel,
  generateFixedKernel67,
  generateFixedKernel68,
  hash,
  dense,
  encoded,
  coords2,
  checkResiduePreflight,
} from "./internal/core.js";
import {
  parseVerificationKey,
  parseProof,
  integer,
  tuple,
  FR,
  FQ,
  type Integer,
} from "./parsers.js";
import { decomposeScalar } from "./glv.js";
import type { Limb, PairingHints, Capsule } from "./index.js";
import type { PreparedKernel } from "./wasm.js";
const k = prepareConstants(constants);
// Host manifest identity only. The compiled Noir key/precomputations remain authoritative.
const CONFIG_DOMAIN = 0x4731365f46495845445f434f4e4649475f563100n;
export const FIXED_CAPSULE_BASE = FIXED_66.capsuleBase;
export interface FixedKeyDescriptor {
  readonly schema: "groth16-fixed-global66-v1";
  readonly verificationKey: unknown;
  readonly tPreimage: readonly Integer[];
}
declare const fixedBrand: unique symbol;
export interface PreparedFixedKey {
  readonly inputCount: number;
  readonly keyHash: bigint;
  readonly configurationHash: bigint;
  readonly [fixedBrand]: true;
}
const states = new WeakMap<
  PreparedFixedKey,
  {
    key: ReturnType<typeof prepareKey>;
    configuration: ReturnType<typeof prepareFixedContext>;
    preimage: bigint[];
  }
>();
function describe(descriptor: FixedKeyDescriptor) {
  if (
    !descriptor ||
    descriptor.schema !== "groth16-fixed-global66-v1" ||
    Object.keys(descriptor).some(
      (x) => !["schema", "verificationKey", "tPreimage"].includes(x),
    )
  )
    throw new Error("Unknown fixed configuration schema");
  const key = prepareKey(parseVerificationKey(descriptor.verificationKey), k);
  const preimage = tuple(descriptor.tPreimage, 12, "fixed preimage").map((x) =>
    integer(x, FQ, "fixed preimage"),
  );
  const configurationHash = hash(
    [CONFIG_DOMAIN, BigInt(key.n), key.keyHash, ...dense(encoded(preimage))],
    k,
  );
  return { key, preimage, configurationHash };
}
/** Developer setup helper, not approval: compare this identity with the manifest for the compiled consumer. */
export function fixedConfigurationHash(descriptor: FixedKeyDescriptor): bigint {
  return describe(descriptor).configurationHash;
}
/** Host mismatch guard. It does not replace the application's on-chain key/statement policy. */
export function prepareFixedKey(
  descriptor: FixedKeyDescriptor,
  expectedConfigurationHash: Integer,
): PreparedFixedKey {
  const { key, preimage, configurationHash } = describe(descriptor);
  if (
    configurationHash !==
    integer(expectedConfigurationHash, FR, "approved configuration hash")
  )
    throw new Error("Fixed configuration does not match approved manifest");
  const configuration = prepareFixedContext(key, preimage, k);
  const handle = Object.freeze({
    inputCount: key.n,
    keyHash: key.keyHash,
    configurationHash,
  }) as PreparedFixedKey;
  states.set(handle, { key, configuration, preimage });
  return handle;
}
export interface FixedHints {
  readonly inputCount: number;
  readonly configurationHash: bigint;
  readonly publicInputs: readonly bigint[];
  readonly raw: readonly Limb[];
  readonly residue: readonly Limb[];
  readonly glvComponents: readonly (readonly bigint[])[];
  readonly accumulators: PairingHints["accumulators"];
  readonly quotient: readonly Limb[];
  readonly blockResiduals: readonly Limb[];
  readonly capsules: {
    readonly private: readonly Capsule[];
  };
}
function freeze<T>(v: T): Readonly<T> {
  if (v && typeof v === "object") {
    for (const x of Object.values(v)) freeze(x);
    Object.freeze(v);
  }
  return v;
}
const fromLimbs = (x: readonly bigint[]) =>
  x[0] + (x[1] << 120n) + (x[2] << 240n);
function fixedRequest(
  raw: readonly Limb[],
  stored: NonNullable<ReturnType<typeof states.get>>,
): Uint8Array {
  // Fixed inputs carry the already approved key's NEGATIVE delta/gamma, then t.
  const values = [
    ...raw.map(fromLimbs),
    ...coords2(stored.key.delta.negate()),
    ...coords2(stored.key.gamma.negate()),
    ...stored.preimage,
  ];
  const bytes = new Uint8Array(960);
  values.forEach((value, i) => {
    let x = value;
    for (let j = 31; j >= 0; j--) {
      bytes[i * 32 + j] = Number(x & 255n);
      x >>= 8n;
    }
  });
  return bytes;
}
function decodeFixed(
  bytes: Uint8Array,
  raw: readonly Limb[],
  schema: CertificateSchema,
) {
  const words = schema.outputBytes / 32;
  if (!(bytes instanceof Uint8Array) || bytes.length !== schema.outputBytes)
    throw new Error(
      `Fixed kernel response must be ${schema.outputBytes} bytes`,
    );
  const values: bigint[] = [];
  for (let i = 0; i < words; i++) {
    let value = 0n;
    for (const b of bytes.subarray(i * 32, (i + 1) * 32))
      value = (value << 8n) + BigInt(b);
    if (value >= (i < words - 2 ? FQ : FR))
      throw new Error("Kernel returned noncanonical field element");
    values.push(value);
  }
  let offset = 12; // The normalized Miller value is diagnostic, not a Noir input.
  const take = (n: number): Limb[] => {
    const out = encoded(values.slice(offset, offset + n)) as Limb[];
    offset += n;
    return out;
  };
  const output = {
    raw,
    residue: take(36),
    accumulators: Array.from({ length: schema.accumulators }, () => take(12)),
    quotient: take(schema.quotient),
    block_residuals: take(9),
  };
  // Cheap inverse/subfield/aggregate preflight, NOT complete verification. Noir
  // must constrain every relation even when an arbitrary callback supplies hints.
  checkResiduePreflight(output.residue.map(fromLimbs));
  const rho = hash(
    [
      schema.domain,
      BigInt(schema.identities),
      ...dense([...raw, ...output.residue, ...output.accumulators.flat()]),
    ],
    k,
  );
  if (rho === 0n) throw new Error("Zero transcript challenge");
  const z = hash([schema.domain + 1n, rho, ...dense(output.quotient)], k);
  if (rho !== values[words - 2] || z !== values[words - 1])
    throw new Error("Fixed kernel transcript mismatch");
  const mod = (v: bigint) => ((v % FQ) + FQ) % FQ;
  const ev = output.quotient.reduceRight(
    (v, x) => mod(v * z + fromLimbs(x)),
    0n,
  );
  let sum = 0n,
    power = 1n;
  const step = mod(rho ** 8n);
  for (const b of output.block_residuals) {
    sum = mod(sum + power * fromLimbs(b));
    power = mod(power * step);
  }
  if (mod(ev * mod(z ** 12n - 18n * z ** 6n + 82n) - sum) !== 0n)
    throw new Error("Kernel aggregate relation mismatch");
  return output;
}
/** Generic fixed-key arithmetic inputs. Application/producer statement schemas are deliberately separate. */
async function prepareFixed(
  request: {
    key: PreparedFixedKey;
    proof: unknown;
    publicInputs: readonly Integer[];
  },
  options: { kernel?: PreparedKernel },
  schema: CertificateSchema,
): Promise<FixedHints> {
  const stored = states.get(request.key);
  if (!stored) throw new Error("Unknown prepared fixed key");
  const inputs = tuple(
    request.publicInputs,
    stored.key.n,
    "fixed public inputs",
  ).map((x) => integer(x, FR, "public input"));
  const prepared = prepareRequest(
    parseProof(request.proof),
    inputs,
    stored.key,
    k,
  );
  const raw = prepared.raw.slice(0, 10) as Limb[];
  const output = options.kernel
    ? decodeFixed(await options.kernel(fixedRequest(raw, stored)), raw, schema)
    : (schema === FIXED_68
        ? generateFixedKernel68
        : schema === FIXED_67
          ? generateFixedKernel67
          : generateFixedKernel)(prepared, stored.configuration, k).data;
  const components = inputs.map((x) => {
    const d = decomposeScalar(x);
    return d.magnitudes.map((v, i) => (d.negative[i] ? -v : v) + (1n << 126n));
  });
  const common: Capsule = {
    scope: 0n,
    slot: schema.capsuleBase + 1n,
    values: [
      ...output.accumulators.flat(2),
      ...output.quotient.flat(),
      ...output.block_residuals.flat(),
    ],
  };
  const glv: Capsule = {
    scope: 0n,
    slot: schema.capsuleBase,
    values: components.flat(),
  };
  return freeze({
    inputCount: stored.key.n,
    configurationHash: request.key.configurationHash,
    publicInputs: inputs,
    raw: output.raw,
    residue: output.residue,
    glvComponents: components,
    accumulators: output.accumulators,
    quotient: output.quotient,
    blockResiduals: output.block_residuals,
    capsules: { private: [glv, common] },
  });
}

export type FixedRequest = Parameters<typeof prepareFixed>[0];
export type FixedOptions = Parameters<typeof prepareFixed>[1];
export function prepareFixedHints(
  request: FixedRequest,
  options: FixedOptions = {},
): Promise<FixedHints> {
  return prepareFixed(request, options, FIXED_66);
}
export async function prepareFixedHints67(
  request: FixedRequest,
  options: FixedOptions = {},
) {
  const hints = await prepareFixed(request, options, FIXED_67);
  return freeze({ ...hints, schema: "groth16-fixed-global67-v1" as const });
}
export const FIXED_PREFIX_CAPSULE_BASE = FIXED_67.capsuleBase;

/**
 * Fixed-only terminal split. No runtime68 format is implied.
 * The common capsule (2,631 fields: accumulators, quotient, residuals) is the
 * explicit-residue layout; pass `residue` as a separate argument. Scaffolded
 * wrappers expect the 2,739-field residue-prefixed capsule from `/current`
 * `createVerifier` in the same slot, so do not send these capsules to them.
 */
export async function prepareFixedHints68(
  request: FixedRequest,
  options: FixedOptions = {},
) {
  const hints = await prepareFixed(request, options, FIXED_68);
  return freeze({ ...hints, schema: "groth16-fixed-global68-v1" as const });
}
export const FIXED_TAIL_CAPSULE_BASE = FIXED_68.capsuleBase;
