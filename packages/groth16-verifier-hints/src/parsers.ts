/** Strict snarkjs BN254 wire parsing. Never use Number for field elements. */
export type Integer = string | bigint;
export type G1 = readonly [bigint, bigint];
export type G2 = readonly [G1, G1];
export const FQ =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
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
export function integer(
  value: unknown,
  modulus: bigint,
  label: string,
): bigint {
  if (
    typeof value !== "bigint" &&
    (typeof value !== "string" ||
      !/^(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value))
  )
    throw new Error(`${label}: expected unsigned decimal/hex string or bigint`);
  const v = BigInt(value as string | bigint);
  if (v < 0n || v >= modulus) throw new Error(`${label}: noncanonical integer`);
  return v;
}
export function tuple(value: unknown, size: number, label: string): unknown[] {
  if (!Array.isArray(value) || value.length !== size)
    throw new Error(`${label}: expected ${size} values`);
  return value;
}
function object(
  value: unknown,
  allowed: string[],
  label: string,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label}: expected object`);
  for (const name of Object.keys(value))
    if (!allowed.includes(name))
      throw new Error(`${label}: unknown property ${name}`);
  const v = value as Record<string, unknown>;
  if (v.protocol !== "groth16" || v.curve !== "bn128")
    throw new Error(`${label}: expected groth16/bn128`);
  return v;
}
function point1(value: unknown, infinity: boolean, label: string): G1 {
  if (!Array.isArray(value) || (value.length !== 2 && value.length !== 3))
    throw new Error(`${label}: G1 arity`);
  const x = integer(value[0], FQ, label),
    y = integer(value[1], FQ, label);
  if (value.length === 3) {
    const z = integer(value[2], FQ, label);
    if (z === 0n) {
      if (!infinity || x !== 0n || (y !== 0n && y !== 1n))
        throw new Error(`${label}: invalid infinity`);
      return Object.freeze([0n, 0n]);
    }
    if (z !== 1n) throw new Error(`${label}: expected affine z=1`);
  }
  if (!infinity && x === 0n && y === 0n)
    throw new Error(`${label}: finite point required`);
  return Object.freeze([x, y]);
}
function point2(value: unknown, label: string): G2 {
  if (!Array.isArray(value) || (value.length !== 2 && value.length !== 3))
    throw new Error(`${label}: G2 arity`);
  const parts = value.map((x) =>
    tuple(x, 2, label).map((y) => integer(y, FQ, label)),
  );
  if (parts.length === 3 && (parts[2][0] !== 1n || parts[2][1] !== 0n))
    throw new Error(`${label}: expected affine G2 z=(1,0)`);
  if (
    parts
      .slice(0, 2)
      .flat()
      .every((x) => x === 0n)
  )
    throw new Error(`${label}: finite point required`);
  return Object.freeze([
    Object.freeze(parts[0]) as G1,
    Object.freeze(parts[1]) as G1,
  ]);
}
// Canonical BN254 G2 generator, snarkjs real/imaginary order. snarkjs `zkey new`
// sets delta_2 = gamma_2 = this point until a phase-2 contribution is made.
const G2_GENERATOR: G2 = [
  [
    10857046999023057135944570762232829481370756359578518086990519993285655852781n,
    11559732032986387107991004021392285783925812861821192530917403151452391805634n,
  ],
  [
    8495653923123431417604973247489272438418190587263600148770280649306958101930n,
    4082367875863433681332203403145435568316851327593401208105741076214120093531n,
  ],
];
function sameG2(a: G2, b: G2): boolean {
  return [0, 1].every((i) => [0, 1].every((j) => a[i][j] === b[i][j]));
}
function negG2(p: G2): G2 {
  return [p[0], [(FQ - p[1][0]) % FQ, (FQ - p[1][1]) % FQ]];
}
/**
 * Reject keys that the verifier would treat as valid but that are degenerate.
 * Affine coordinates are canonical (each below FQ), so coordinate equality is
 * point equality. These checks do not detect a key whose trapdoor is known.
 */
function checkKeyRelations(key: VerificationKey): void {
  const { vk_gamma_2: gamma, vk_delta_2: delta } = key;
  // delta = +-gamma: A = alpha, B = beta, C = -+L satisfies the pairing
  // equation for every public input, with all operands finite.
  if (sameG2(delta, gamma) || sameG2(delta, negG2(gamma)))
    throw new Error(
      "key: delta equals plus or minus gamma; anyone can forge proofs (phase-2 contribution missing?)",
    );
  // delta = +-generator has the public trapdoor +-1. The generator is also the snarkjs
  // marker of a key without a phase-2 contribution.
  if (sameG2(delta, G2_GENERATOR) || sameG2(delta, negG2(G2_GENERATOR)))
    throw new Error(
      "key: delta is plus or minus the G2 generator; the key has no phase-2 contribution",
    );
  // The verifiers require a finite L = IC0 + sum(x_i IC_i). When every IC
  // point is infinity, L is infinity for every input and every proof fails.
  if (key.IC.every(([x, y]) => x === 0n && y === 0n))
    throw new Error(
      "key: every IC point is infinity, so L is always infinity and the verifier rejects every proof",
    );
}
/**
 * Encoding checks plus key relations: delta must differ from +-gamma and from
 * +-the G2 generator, and at least one IC point must be finite. prepareRuntimeKey /
 * prepareRuntimeHints also check curve and subgroup membership.
 */
export function parseVerificationKey(value: unknown): VerificationKey {
  const v = object(
    value,
    [
      "protocol",
      "curve",
      "nPublic",
      "vk_alpha_1",
      "vk_beta_2",
      "vk_gamma_2",
      "vk_delta_2",
      "IC",
      "vk_alphabeta_12",
    ],
    "key",
  );
  if (
    typeof v.nPublic !== "number" ||
    !Number.isSafeInteger(v.nPublic) ||
    v.nPublic < 0 ||
    v.nPublic > 256
  )
    throw new Error("key: nPublic must be an integer from 0 to 256");
  // snarkjs includes this redundant cache. Validate its wire shape but never use it.
  if (v.vk_alphabeta_12 !== undefined)
    for (const a of tuple(v.vk_alphabeta_12, 2, "alpha-beta cache"))
      for (const b of tuple(a, 3, "alpha-beta cache"))
        for (const c of tuple(b, 2, "alpha-beta cache"))
          integer(c, FQ, "alpha-beta cache");
  const key: VerificationKey = Object.freeze({
    protocol: "groth16",
    curve: "bn128",
    nPublic: v.nPublic,
    vk_alpha_1: point1(v.vk_alpha_1, false, "alpha"),
    vk_beta_2: point2(v.vk_beta_2, "beta"),
    vk_gamma_2: point2(v.vk_gamma_2, "gamma"),
    vk_delta_2: point2(v.vk_delta_2, "delta"),
    IC: Object.freeze(
      tuple(v.IC, v.nPublic + 1, "IC").map((x, i) =>
        point1(x, true, `IC[${i}]`),
      ),
    ),
  });
  checkKeyRelations(key);
  return key;
}
export function parseProof(value: unknown): Proof {
  const v = object(
    value,
    ["protocol", "curve", "pi_a", "pi_b", "pi_c"],
    "proof",
  );
  return Object.freeze({
    protocol: "groth16",
    curve: "bn128",
    pi_a: point1(v.pi_a, false, "A"),
    pi_b: point2(v.pi_b, "B"),
    pi_c: point1(v.pi_c, false, "C"),
  });
}
