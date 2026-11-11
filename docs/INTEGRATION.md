# Integrating a Groth16 verifier into an Aztec application

From a snarkjs BN254 verification key to a verified Aztec private call: choose a
profile, generate the trusted key material and a consumer contract, prepare
hints, and call the consumer. This is the Aztec v6 layer of the host tooling;
plain Noir programs need only the key generator and the hint SDK (see the
[README](../README.md)). Commands run from the repository root with
`PYTHONPATH=packages/groth16-verifier-hints/python` after installing the SDK's
dependencies (`npm ci --ignore-scripts --prefix packages/groth16-verifier-hints`).
Generation needs Python 3.10+ and Node, and runs no compiler or prover.
The [security contracts](SECURITY.md) state what the caller must still do.

## Profiles

A profile fixes one verifier along two independent axes. Start with
**private + fixed** for a known circuit.

| `mode` | Execution | Backend (`toolchain.backend`) |
| --- | --- | --- |
| `private` | Verify inside one Aztec private function | `stock-v6`: Aztec v6.0.0 `0219f11d8133970df3974fe5ae65e006bf8c193a` |
| `offchain` | An UltraHonk producer proves the verification; one private function checks that proof | `stock-v6` |

`keyPolicy: fixed` compiles the key and its preprocessing into the circuit as a
generated trusted provider (certificate `groth16-fixed-global68-v1`, plus a
`configurationHash` of the key and alpha-beta preimage). `runtime` takes the key as
an input; the consumer authorizes its canonical key hash (certificate
`groth16-runtime-global68-v1`, `configurationHash` null). The generated examples pin
one approved key; the arithmetic API admits richer policies. `inputCount` is a
compile-time dimension from 0 to 256.

The manifest (schema `groth16-verifier-profile-v2`,
`packages/groth16-verifier-hints/schemas/consumer.schema.json`) holds configuration only:

```json
{
  "schema": "groth16-verifier-profile-v2",
  "name": "multiplier", "mode": "private", "keyPolicy": "fixed", "inputCount": 1,
  "certificate": "groth16-fixed-global68-v1",
  "keyHash": "0", "configurationHash": "0",
  "statementSchema": "groth16-verifier-statement-v1",
  "toolchain": {
    "aztecCommit": "0219f11d8133970df3974fe5ae65e006bf8c193a",
    "noirCommit": "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7",
    "backend": "stock-v6"
  },
  "domain": "finite-pairing-operands-v1"
}
```

The zeros only illustrate types; generation writes the real canonical decimals.
Both modes use the stock bb 6.0.0 backend `stock-v6` and its one Aztec source
(`backends` in `toolchain-v6.json`); v1 profiles are rejected. Profiles, key hashes and digests
are trusted application configuration, never authorization because they arrived
with a proof. The SDK validates them before any hint or backend work and fails
early on unknown modes or schemas, wrong arity, a wrong key or preprocessing
identity, mismatched compiler pins or a mismatched backend declaration. These host
checks do not replace the constrained and application checks.

**Statement.** `groth16-verifier-statement-v1` is Poseidon2 over the runtime-schema
domain, N, the canonical key hash, six application fields (chain ID, version,
consumer address, action, beneficiary, nonce, in that order) and the N public
inputs; fixed wrappers use the compiled key hash. It is a digest of caller
arguments, not a value the proof attests: anyone holding a proof can resubmit it
with another action, beneficiary or nonce unless the original Groth16 circuit
exposes those as public inputs. The consumer checks chain, version and its own
address; the application defines public-input meaning, actions and replay.

## Toolchain

Pins are in [`toolchain-v6.json`](../toolchain-v6.json): Noir `5a7ee9bf5ed8973076df7bb0d2b723024db09ae7`
(reports `nargo 1.0.0-rc.3`), Aztec `0219f11d8133970df3974fe5ae65e006bf8c193a`
(v6.0.0) and Aztec labs `d2e67c1d938f06a6476dd7d4bd01e73771923dd1`.

```sh
python3 scripts/groth16-doctor.py --nargo /path/to/pinned/nargo --json
```

The doctor only inspects versions and Git heads. It selects the compiler from
`--nargo`, then `G16_NARGO`, then `PATH`, and fails rather than falling back when
the selected one is wrong. A matching version is self-reported compatibility;
only `pinned_binary_match` (SHA-256) identifies the recorded binary. `--bb` /
`G16_BB` records an optional backend; `--aztec-source` / `G16_AZTEC_SOURCE` and
`--labs-source` / `G16_LABS_SOURCE` (with `--require-aztec`) check source heads.
Support tools reuse `groth16.toolchain.resolve_nargo()`, which returns a
`ResolvedTool` (`executable`, `selection`, `version`, `commit`, `sha256`,
`pinned_binary_match`) or raises `ToolchainError`.

## Generate key material

```sh
python3 -m groth16.generate --vk fixtures/multiplier/verification_key.json \
  --out /fresh/multiplier-key --name multiplier --mode private --key-policy fixed
```

The key's origin is an application trust decision. The generator checks
encoding, arity, curve and G2 subgroup membership, and rejects degenerate keys:
delta equal to plus or minus gamma (anyone can forge proofs), delta equal to the G2
generator (a snarkjs key before any phase-2 contribution) and all-infinity IC (every
proof rejected). IC0 at infinity is accepted with a `GenerationWarning` and a
`limitations` entry: inputs whose L is infinity, such as all zeros, cannot be
proved. No check detects a retained trapdoor; use keys from a contributed phase 2.
Validation raises errors, so `python -O` keeps it.

The output directory must not exist; the result is installed only after validation
and is deterministic for the same inputs and tool sources.

| File | Purpose |
| --- | --- |
| `application_key.nr` | Fixed-policy trusted provider; copy into the application's `src` |
| `key.json`, `key.ts` | Matching descriptor for `groth16-verifier-hints/current` |
| `profile.json` | Execution, key and toolchain configuration |
| `preprocessing.json` | Fixed preprocessing checks, table cardinality and lineage |
| `generation.json` | Input, normalized key, output and tool hashes; canonical profile hash |

`--dependency-alias` (default `groth16`) and `--provider-name` (default
`ApplicationKey`) set the provider's import alias and type. `--key-policy runtime`
writes the normalized key, descriptor and profile with no provider or
preprocessing. The Python API is `groth16.generate.generate(vk_path, out_dir, *,
name, provider_name, dependency_alias, mode, key_policy, node)` and returns the
`generation.json` record. For N>0 preprocessing supplies 136*N+1 matched
offset/correction pairs; N=0 keeps the direct trusted IC0 path.

## Generate a consumer

One private function (`private` mode, either key policy):

```sh
python3 -m groth16.scaffold --vk fixtures/multiplier/verification_key.json \
  --out /fresh/multiplier-contract --name multiplier --mode private --key-policy fixed \
  --aztec /path/to/pinned/aztec-node/noir-projects/aztec-nr/aztec
```

The contract has one private `verify` using the public verifier, app-local key
material and the schema commitment, plus its own README and a `scaffold.json`
binding template, source and profile hashes. For N>0, `verify` takes
`statement, application, public_inputs`, then `raw` (fixed) or `key, proof`
(runtime), and returns `public_inputs`. It returns verified data; it does not
spend a nullifier or authorize an action.

An offchain producer and its consumer (`offchain` mode):

```sh
python3 -m groth16.producer --vk fixtures/multiplier/verification_key.json \
  --out /fresh/multiplier-offchain --name multiplier --key-policy fixed \
  --aztec /path/to/pinned/aztec-node/noir-projects/aztec-nr/aztec
```

The output has `producer/` (ordinary Noir running the complete private verifier),
`consumer/` (one Aztec private function), `generated/` (profile and key material)
and `scaffold.json`. Both sides bind the approved Groth16 key hash. The consumer
constructor takes only `producer_key_hash`, which you derive from the exact
compiled producer and authenticate yourself. The consumer ABI is
`statement, application, public_inputs, producer_key, proof`; the recursive
verifier takes 115 key fields, 458 proof fields and the single public input
`[statement]` (the eight DefaultIO accumulator inputs are separate).

**Zero public inputs.** Pinned Noir forbids empty arrays in entry-point ABIs, so
N=0 wrappers omit `public_inputs` (and the producer's empty GLV arrays), build
`[]` internally and return `statement` instead. The SDK selects this ABI;
`packet.publicInputs` is still `[]`. Never substitute an N=1 contract with a zero
input.

**Artifact records.** After compiling, record artifact identities with
`python3 -m groth16.artifacts` (schema `groth16-verifier-artifacts-v1`,
[artifacts.schema.json](../packages/groth16-verifier-hints/schemas/artifacts.schema.json)). A record binds the
profile SHA-256 (over recursively key-sorted compact UTF-8 JSON, unknown fields
and noncanonical decimals rejected) to `artifactSha256` (whole file),
`bytecodeSha256` (base64-decoded ACIR of the verification function) and
`verificationKeySha256` (serialized key bytes, or `null` before derivation; this
file identity differs from the field-valued key hash used in recursion). Roles are
`private-consumer`, plus `producer` for `offchain`. A record with a null key identity is
not release-ready recursive policy. Re-derive the producer key after any
executable change; equal gate counts do not imply equal keys.

## Prepare hints and call

```ts
import {createVerifier} from 'groth16-verifier-hints/current';
const verifier = createVerifier(profile, key, {backend: 'stock-v6'});
const packet = await verifier.prepare({proof, publicInputs, application});
```

`key` is the fixed descriptor or the runtime verification key. Field values are
`bigint` or canonical decimal/hex strings, never JavaScript numbers. Only packets
from `/current` match generated consumers (see the
[SDK reference](../packages/groth16-verifier-hints/README.md) for capsule layouts and the
other entries).

`private`, through the application's own pinned v6 SDK and contract:

```ts
import {preparePrivateCall} from 'groth16-verifier-hints/aztec';
import {Fr} from '@aztec-labs/foundation/curves/bn254';
import {AztecAddress} from '@aztec-labs/stdlib/aztec-address';
import {Capsule} from '@aztec-labs/stdlib/tx';
const interaction = preparePrivateCall(profile, packet, contract, {Fr, AztecAddress, Capsule});
```

The adapter calls `contract.methods.verify(...).with({capsules})`, with capsules
bound to the contract address at scope zero (they remain untrusted witnesses). It
does not submit, touch wallet storage or create a second Barretenberg instance.

`offchain`, with caller-owned NoirJS and UltraHonk factories:

```ts
import {createProducer} from 'groth16-verifier-hints/producer';
import {prepareOffchainCall} from 'groth16-verifier-hints/aztec';
const producer = await createProducer({
  profile, artifactBytes, manifest,
  executor: artifact => new Noir(artifact),
  backend: bytecode => new UltraHonkBackend(bytecode, bbApi),
});
const certificate = await producer.prove(packet); // witness, proof and local verification
const interaction = prepareOffchainCall(profile, packet, certificate, contract, approvedProducerKeyHash);
```

The target is `noir-recursive` with zero knowledge. The pinned
`generateRecursiveProofArtifacts` returns an empty `proofAsFields`, so the producer
adapter derives the recursive field encoding itself, after checking artifact,
bytecode and key bytes against the manifest, canonical field encodings, the single
statement and local verification. The caller owns the backend instance's lifetime.
Loading untrusted JavaScript or WASM is outside the proof boundary.

[fixtures/multiplier](../fixtures/multiplier/) holds a saved development-setup
proof of a multiplier with public output 33, which the tests use.
