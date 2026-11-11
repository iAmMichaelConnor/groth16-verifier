/** Canonical-field Poseidon2 transcript primitive shared by protocol adapters.
 * Hashing alone does not authenticate application policy or bind a circuit. */
import { constants } from "./internal/constants.js";
import { hash, prepareConstants } from "./internal/core.js";
import { FR, integer, type Integer } from "./parsers.js";
const prepared = prepareConstants(constants);
export function poseidon2Hash(values: readonly Integer[]): bigint {
  if (!Array.isArray(values))
    throw new Error("Transcript must be a field array");
  return hash(
    values.map((value) => integer(value, FR, "transcript field")),
    prepared,
  );
}
