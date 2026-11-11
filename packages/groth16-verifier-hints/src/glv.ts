import { FR, integer, type Integer } from "./parsers.js";
const U0 = 147946756881789319000765030803803410728n,
  U1 = -9931322734385697763n;
const V0 = 9931322734385697763n,
  V1 = 147946756881789319010696353538189108491n;
const LAMBDA =
  21888242871839275217838484774961031246154997185409878258781734729429964517155n;
/** Nearest lattice-plane split. Both signed components have magnitude < 2^126. */
export function decomposeScalar(value: Integer) {
  const k = integer(value, FR, "scalar"),
    a = (k * V1 + FR / 2n) / FR,
    b = (-k * U1 + FR / 2n) / FR;
  const x = k - a * U0 - b * V0,
    y = -a * U1 - b * V1;
  const magnitudes = [x < 0n ? -x : x, y < 0n ? -y : y] as const;
  if (
    magnitudes.some((v) => v >= 1n << 126n) ||
    (x + LAMBDA * y - k) % FR !== 0n
  )
    throw new Error("GLV decomposition invariant failed");
  return Object.freeze({
    magnitudes: Object.freeze(magnitudes),
    negative: Object.freeze([x < 0n, y < 0n] as const),
  });
}
