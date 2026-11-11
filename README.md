> [!WARNING]
> **This code has not been audited.** It is experimental software, provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A bug can leave a circuit under-constrained, so that invalid proofs are accepted. Do not rely on it to protect real assets or sensitive data without your own independent review.

> [!NOTE]
> This is an independent project. It is not affiliated with, sponsored by or endorsed by Succinct (SP1), iden3 (Circom, snarkjs) or any other project named here. Names belong to their owners and are used only to say what this software works with.

# groth16-verifier

**Verify a Groth16 proof inside a Noir circuit.** Anything proven with Circom or
SP1 becomes something a Noir program or an Aztec contract can check, with stock
`nargo` and `bb`.

For example, you can:

- Verify a Groth16 proof (BN254), with its public inputs.
  - E.g. Circom / snarkjs.
- Verify an SP1 v5 or v6 proof, so that a Rust program proven with SP1 can be
  checked in Noir.
- Keep the Groth16 proof and its public inputs _private_ from the verifier of the outer Noir circuit.
- For the smallest circuit, hard-code the Groth16 verification key into the Noir circuit.
- Or supply the verification key at runtime to a slightly larger circuit.
- Use the BN254 arithmetic on its own: the optimal ate pairing, the Fp, Fp2, Fp6, Fp12 tower, G1 and G2
  points, an MSM.

A verifier checks the full Groth16 statement: the public inputs are bound to the
input point `L = IC[0] + sum inputs[i] * IC[i+1]`, and the pairing equation
`e(A, B) e(C, -delta) e(L, -gamma) e(-alpha, beta) = 1` is checked with a
hinted certificate (after Novakovic and Eagen, ["On Proving
Pairings"](https://eprint.iacr.org/2024/640)) rather than by computing the
pairing. The hints are computed off-circuit by the [hint SDK](packages/groth16-verifier-hints)
and are untrusted: the circuit constrains every one of them.

## What is in the repository

**Where it runs.**

- **Works in plain Noir** (stock `nargo` and stock `bb`, no Aztec):
  every Noir package in this repository, including `groth16::verify`,
  `runtime_verifier::verify` and `sp1`. The tests and benchmarks run on stock
  Noir 1.0.0 and bb 6.0.0.
- **Needs Aztec:** no Noir package. Parts of the host tooling target Aztec v6:
  the hint SDK's profile layer (`/current`, `/aztec`, `/producer`) and the
  Python `groth16.scaffold` and `groth16.producer` generators, which write
  Aztec contracts; see [docs/INTEGRATION.md](docs/INTEGRATION.md).

| Package | Contents |
| --- | --- |
| [`groth16`](noir/groth16) | Fixed-key verifier: `verify::<Key, N>`, the `FixedKey` trait and the `provider` types a generated key uses. |
| [`runtime_verifier`](noir/runtime_verifier) | Runtime-key verifier: `verify(key, inputs, proof, hints)` returns the key hash, plus `Hints`, `RawVerificationKey`, `key_commitment`, `assert_authorized_key`, `statement_id`. |
| [`runtime_key_schema`](noir/runtime_key_schema) | Canonical runtime-key encoding and the key, input and statement commitments (re-exported by `runtime_verifier`) |
| [`sp1`](noir/sp1) | SP1 v5: the pinned key `Sp1Key` and `sp1_public_inputs`. SP1 v6: the module `v6`, with the complete entry point `v6::verify`, `v6::public_inputs` and `v6::VK_ROOT` (its key is private) |
| [`bn254_fields`](noir/bn254_fields) | `Fp`, `Fp2`, `Fp6`, `Fp12`: BN254 Fq and its extension tower |
| [`bn254_g1`](noir/bn254_g1) | G1 points, group arithmetic, on-curve checks, a constrained MSM |
| [`bn254_g2`](noir/bn254_g2) | G2 points on the twist, Frobenius maps, subgroup checks, line evaluations |
| [`bn254_pairing`](noir/bn254_pairing) | The optimal ate pairing: `pairing`, `pairing_multi`, `miller_loop`, `final_exponentiation`. Tested unconstrained only: a constrained pairing test needs far more memory than a hosted runner has ([CONTRIBUTING](CONTRIBUTING.md#tests)). |
| [`bn254_pairing_checks`](noir/bn254_pairing_checks) | Building blocks of the hinted pairing certificate; not a verifier on their own |

`noir/internal/` holds support packages (modified copies of noir-bignum and
noir_bigcurve, the runtime G1 and pairing adapters). They are
not public API; depend on the packages above and nargo resolves them.

## Compatibility

The Noir packages are tested with Noir 1.0.0-rc.3, the minimum supported
version (what Aztec 6.0.0 ships), and with Noir 1.0.0, the latest release, on
every pull request, and with Noir nightly every night. Keep this in sync with
the `toolchain` matrix in `.github/workflows/test.yml`.

The SP1 verifiers each pin one SP1 Groth16 key:

| Verifier | Accepts proofs from | Groth16 key (`groth16_vk.bin`, SHA-256 prefix) |
| --- | --- | --- |
| `sp1::Sp1Key` with `sp1_public_inputs` | SP1 v5.0.0 to v5.2.4 | `a4594c59` |
| `sp1::v6::verify` | SP1 v6.1.0 to v6.10.0 (SP1 circuit version v6.1.0) | `4388a21c` |

SP1 v6.0.0 to v6.0.2 (circuit version v6.0.0, key `0e78f4db`) use another key
and verification-key root, and neither verifier accepts their proofs. A later
SP1 release that changes the key or the root needs a new pinned key.

## Installation

In your `Nargo.toml`, add the packages you need. Each lives in its own
directory of this repository:

```toml
[dependencies]
groth16 = { git = "https://github.com/iAmMichaelConnor/groth16-verifier", tag = "v0.1.0", directory = "noir/groth16" }
runtime_verifier = { git = "https://github.com/iAmMichaelConnor/groth16-verifier", tag = "v0.1.0", directory = "noir/runtime_verifier" }
sp1 = { git = "https://github.com/iAmMichaelConnor/groth16-verifier", tag = "v0.1.0", directory = "noir/sp1" }
bn254_pairing = { git = "https://github.com/iAmMichaelConnor/groth16-verifier", tag = "v0.1.0", directory = "noir/bn254_pairing" }
```

Use one tag for every package from this repository, so that shared types (the
field and curve types, the key schema) have one identity.

## Usage

### Fixed-key verification

Generate the key's provider module once, from a snarkjs verification key you
trust (in a checkout of this repository; Python 3.10+ and Node, after
`npm ci --ignore-scripts --prefix packages/groth16-verifier-hints`), and copy
`application_key.nr` into your crate:

```bash
PYTHONPATH=packages/groth16-verifier-hints/python python3 -m groth16.generate \
  --vk verification_key.json --out generated --name myapp --mode private --key-policy fixed
```

Then verify in the circuit. `raw` holds A, B, C and the input point L as
120/120/14-bit Fq limbs; the other arguments are hints:

```rust
mod application_key;
use application_key::ApplicationKey;

fn main(
    inputs: pub [Field; 1],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 1],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) {
    groth16::verify::<ApplicationKey, 1>(
        inputs, raw, residue, components, accumulators, quotient, block_residuals,
    );
}
```

The hint SDK prepares these arguments from a snarkjs proof
(`createVerifier(profile, key).prepare(...)` and `toNoirInput(packet.producerInputs)`
in `groth16-verifier-hints/current`; see the [SDK README](packages/groth16-verifier-hints/README.md)).

### Runtime-key verification

The key is a circuit input, so one circuit verifies proofs for any key with
`N` public inputs. `verify` returns the key's canonical hash
(`key_commitment`); **it must be checked against a key you trust**, because
anyone can make a valid proof under a key of their own choosing. Here it is a
public output that the outer verifier compares with the trusted hash:

```rust
use runtime_verifier::{Hints, RawVerificationKey};

fn main(
    inputs: pub [Field; 2],
    key: RawVerificationKey<2>,
    proof: [[u128; 3]; 8],
    hints: Hints<2>,
) -> pub Field {
    runtime_verifier::verify(key, inputs, proof, hints)
}
```

The hint SDK prepares `key`, `proof` and `Hints` from the snarkjs key, proof
and public inputs. Its preparation calls also take six "application" fields
for an Aztec statement digest; a circuit that does not use that digest can
pass any field values.

### SP1 proofs

```rust
use sp1::{Sp1Key, sp1_public_inputs};

let inputs = sp1_public_inputs(program_vkey, public_values); // [vkey, sha256 digest masked to 253 bits]
groth16::verify::<Sp1Key, 2>(inputs, raw, residue, components, accumulators, quotient, block_residuals);
```

For SP1 v6, `v6::verify` derives the five public inputs itself: the program
key, the masked SHA-256 of the public values, exit code 0, the pinned
`v6::VK_ROOT` and the proof's nonce:

```rust
sp1::v6::verify(program_vkey, public_values, proof_nonce, raw, residue, components, accumulators, quotient, block_residuals);
```

The SP1 v6 key is not exported: `groth16::verify` with hand-built inputs
would skip the exit-code and root pins.

A valid proof says only that some SP1 program with that program key produced
those public values. What the calling circuit must still do:

- **Pin the program vkey.** Compare `program_vkey` with the vkey of the program
  you trust. It is the canonical field element of SP1's 32-byte vkey hash; the
  host package rejects values at or above the BN254 scalar modulus, as SP1's
  Solidity verifier does.
- **Bind and interpret the public values.** The proof commits to their
  SHA-256; decode them in the circuit and bind what they mean.
- **Provide replay protection.** For SP1 v6 the proof nonce is chosen by
  whoever requested the proof (zeros by default) and is bound but not checked.
  Do not use it as a nullifier or for replay protection, and pass it as a
  private witness.
- **Track SP1.** A circuit with a compiled-in key keeps accepting proofs for
  that SP1 circuit version (v6.1.0 for `v6::verify`) until you ship a new
  circuit: there is no revocation. You inherit the soundness of that SP1
  circuit version and its trusted setup, so follow SP1's security advisories.

[`groth16-verifier-sp1`](packages/groth16-verifier-sp1) parses SP1 v5 and v6
proof bytes and prepares the hints.

## Benchmarks

Circuit size (`bb gates` `circuit_size`, before power-of-two padding) of each
`#[export]` benchmark function, measured with Noir 1.0.0 and bb 6.0.0 on
2026-11-10 (`groth16_verify_1` and `sp1_v6_verify` on 2026-11-11). The arithmetic rows include range
checks on their inputs and outputs and the backend's fixed per-circuit cost, so
they are not additive.
The [benchmark workflow](.github/workflows/benchmark.yml) reports current
numbers on every pull request and records history on the `gh-pages` branch.

| Benchmark | Operation | Circuit size |
| --- | --- | ---: |
| `groth16_verify_1` | Fixed-key verification, Circom key, 1 public input | 188,966 |
| `sp1_verify` | Fixed-key verification, SP1 v5 key, 2 public inputs | 216,777 |
| `sp1_v6_verify` | Fixed-key verification, SP1 v6 key, 5 public inputs | 300,213 |
| `runtime_verify_1` | Runtime-key verification, 1 public input | 438,862 |
| `runtime_verify_2` | Runtime-key verification, 2 public inputs | 491,775 |
| `bn254_fp_mul` | Fq multiplication | 2,961 |
| `bn254_fp2_mul` | Fq2 multiplication | 3,118 |
| `bn254_fp6_mul` | Fq6 multiplication | 4,367 |
| `bn254_fp12_mul` | Fq12 multiplication | 7,883 |
| `bn254_g1_add` | G1 affine addition (on-curve inputs) | 7,756 |
| `bn254_g2_double` | G2 Jacobian doubling (on-twist input) | 5,247 |

`sp1_verify` and `sp1_v6_verify` exclude the SHA-256 of the public values that
`sp1_public_inputs` and `sp1::v6::verify` add.

To generate the report locally:

```bash
./scripts/build-gates-report.sh
```

## Security

If you find a vulnerability, please **do not** open a public issue. Report it
privately via [GitHub's "Report a vulnerability"](https://github.com/iAmMichaelConnor/groth16-verifier/security/advisories/new)
form instead.

- **Bind meaning.** The original Groth16 circuit must fix what its public
  inputs mean. Verifying a proof does not authorise an action, a beneficiary
  or a nonce, and does not prevent replay: proofs are malleable, so a new
  proof of the same statement has different bytes. The consuming application
  does that.
- **Authorise the key.** A generated `FixedKey` provider is trusted code; the
  trait cannot check a handwritten one. A runtime key is only as good as the
  application's check of the hash `runtime_verifier::verify` returns.
- **SP1.** A compiled-in SP1 key is never revoked, and the SP1 entry points
  check only what SP1's onchain verifier checks; see [SP1 proofs](#sp1-proofs)
  for what the calling circuit must still do.
- **Use a complete entry point.** A pairing-product check without the
  public-input binding accepts `A = C = L = alpha`, `B = beta + gamma + delta`
  for every key. Only the complete `verify` entry points are exported; the
  partial helpers are not, and `scripts/check-public-api.sh` checks that.
- **Point policy.** A, B, C and the computed L must be finite. Zero public
  inputs and unused IC entries at infinity are accepted.
- **Key preprocessing.** The generator rejects degenerate keys (delta equal to
  plus or minus gamma, delta equal to the G2 generator, all-infinity IC) but
  cannot detect a retained setup trapdoor. Use keys from a contributed phase 2.
- **What the proof-vector tests show.** The `tests/*_multiplier_vector` crates
  run each verifier on one saved Circom proof. It verifies. A changed public
  input is rejected by the input binding. The proof with A or B negated, which
  still passes the point checks and the input binding, and the valid proof with
  a forged certificate (ones and zeros), are rejected by the pairing check;
  `scripts/tests/heavy_constraints_without_hint_guard.py` reruns the honest
  proof, the proof with A negated and the forged certificate with the honest
  hint's self-check removed and shows that the constraints reject the latter
  two too (negated B reaches the same check as negated A). No test runs the pairing check on a false statement with a
  certificate computed for that statement, because none exists: the SDK cannot
  prepare a certificate for a pairing product that is not one, and
  constructing a satisfying one would break the verifier. That no such
  certificate exists is the soundness argument in
  [docs/OPTIMISATIONS.md](docs/OPTIMISATIONS.md), which tests do not replace.
  For SP1 v6, `tests/sp1_v6_vector` and the `sp1` package's tests run two
  saved SP1 v6 proofs. Both verify. Each of the five public inputs, changed
  with its GLV components recomputed, is rejected by the input MSM, and, with
  the input point moved to match, by the pairing check; the probe reruns the
  honest proof and the proof with A negated. The A, B, C of an SP1 v5 or SP1 v6.0.0 proof fail the pairing check
  for a v6 statement, and `scripts/tests/test_sp1_v6_cross_version.py` checks
  at the pairing level that the SP1 v6.0.0 proof, with its own inputs, holds
  under its own key and not under the pinned one.

[docs/SECURITY.md](docs/SECURITY.md) states these contracts in full, and
[docs/OPTIMISATIONS.md](docs/OPTIMISATIONS.md) gives the equations, bounds and
exceptional-case arguments behind the arithmetic. Third-party code is listed in
[NOTICE](NOTICE).

## License

The code written for this repository is licensed under Apache-2.0 (see
[LICENSE](LICENSE)). [NOTICE](NOTICE) lists the third-party code and data it
contains and the licence of each; the code adapted from bankaixyz/noir_groth16
has no licence file upstream.
