# SP1 v5 and v6 host integration

`groth16-verifier-sp1` provides `prepareSp1Key`, `parseSp1ProofBytes`, `sp1PublicInputs` and explicit `prepareSp1Hints68`. These are for the pinned SP1 v5 key, not for every SP1 revision or arbitrary Groth16 application; the SP1 v6 functions are [below](#sp1-v6).

The wire parser accepts exactly 260 bytes: selector `a4594c59` plus eight field words. It reverses Ethereum Fq2 coefficient order into snarkjs order and rejects wrong selectors, malformed lengths and noncanonical coordinates. The application convention is exactly 32 public-value bytes with inputs `[programVkey, SHA256(publicValues) & (2^253-1)]`. Its producer statement follows the retained SP1-specific schema (`Poseidon2("GR16_SINGLE_V6\x01", application[6], vkey, publicValues[32])`), a distinct schema from the generic profile statement. No Noir circuit in this repository computes that statement: the SP1 Noir entries take vkey and public values but no statement or application. Treat `producer.statement` as unauthenticated host metadata unless your own circuit recomputes it with exactly this domain and layout.

```ts
import { prepareSp1Key, prepareSp1Hints68 } from 'groth16-verifier-sp1';
import { toNoirInput } from 'groth16-verifier-hints';

const hints = await prepareSp1Hints68({
  key: prepareSp1Key(), proof: snarkjsProof, vkey: programVkey,
  publicValues: publicValueBytes,
  application: [chainId, version, consumerAddress, action, beneficiary, nonce],
});
const producerInputs = toNoirInput(hints.producer);
```

## SP1 v6

`prepareSp1V6Key`, `parseSp1V6ProofBytes`, `sp1V6PublicInputs` and `prepareSp1V6Hints` serve the Noir entry point `sp1::v6::verify`, for SP1 circuit version v6.1.0 (SP1 v6.1.0 to v6.10.0). The parser accepts exactly 356 bytes, as `SP1ProofWithPublicValues::bytes()` returns them: selector `4388a21c`, then the exit code, the verification-key root and the proof nonce as 32-byte words, then the eight proof words. It rejects another selector (SP1 v5 and v6.0.0 proofs among them), a nonzero exit code, a root other than `SP1_V6_VK_ROOT` and noncanonical words, as SP1's onchain verifier does, and A, B, C at infinity or off their curves. Public values may have any length; the five public inputs are `[programVkey, SHA256(publicValues) & (2^253-1), 0, SP1_V6_VK_ROOT, nonce]`.

```ts
import { prepareSp1V6Hints } from 'groth16-verifier-sp1';
import { toNoirInput } from 'groth16-verifier-hints';

const hints = await prepareSp1V6Hints({ proof: proofBytes, vkey: programVkey, publicValues });
const args = toNoirInput(hints.arguments); // the arguments of sp1::v6::verify, by name
```

The tests run on the saved SP1 v6 proofs in `fixtures/sp1-v6`.

What these functions do not do, and the circuit that calls `sp1::v6::verify` must:

- pin the program vkey (`vkey` is the canonical field element of SP1's 32-byte vkey hash; values at or above the BN254 scalar modulus are rejected, as SP1's Solidity verifier does);
- bind and interpret the public values;
- provide replay protection. The proof nonce is chosen by the prover (zeros by default) and is bound but not checked; do not use it as a nullifier or for replay protection, and pass it as a private witness.

There is no revocation: a circuit compiled with this key accepts proofs for SP1 circuit version v6.1.0 until the application ships a new circuit, so it inherits the soundness of that SP1 circuit version and its trusted setup; follow SP1's security advisories.

A new SP1 revision needs its own approved key/configuration and matching consumer, not merely a changed selector. Saved test vectors live in this repository and are not installed runtime dependencies. No proof or transaction is created by the calls above.

The adapter consumes the public `groth16-verifier-hints` fixed-key, parser,
transcript and optional WASM APIs. It uses the same generic preparation pipeline;
there is no separate pairing implementation. Unsuffixed preparation uses the
global66 schema; the explicit global67/global68 functions use their matching schemas.

For local setup, build the generic SDK first, then run `npm ci --ignore-scripts`
and `npm run build` in this package. `npm test` runs the exact saved-vector,
configuration, wire-format and input-domain checks without proving or key generation.
The private local dependency is for workspace setup. Distribution tests install
both packed packages into a disposable consumer outside the checkout.

## Python witness script

`python/sp1_v6.py` parses SP1 v6 proof bytes and derives the five public
inputs with the same rules as the TypeScript adapter; the vector generator
uses it.

`python/sp1.py` maps SP1 v5 public values and proof coordinates to the generic
Groth16 arithmetic in `packages/groth16-verifier-hints/python/groth16/`,
computes pairing hints and checks them before writing JSON or TOML. Its decoder
accepts public values of any length and a permissive proof envelope; use the
TypeScript parser above when the strict SP1 wire format matters. Neither path
creates a proof.
