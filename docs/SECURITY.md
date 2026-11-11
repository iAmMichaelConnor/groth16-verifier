# Groth16 security contracts

This implementation is experimental and unaudited. The following contracts are
necessary conditions, not a formal proof of the compiler, backend, every generic
arithmetic routine or all possible caller-defined providers.

## Arithmetic and transcript

External field encodings are canonical: every proof, key and claimed-point
coordinate is decoded with 120/120/14-bit limb checks and a strict `< q` check.
Internal BigNum values may be bounded noncanonical representatives (any value
below `2^254`) where the API permits them: certificate accumulators, quotient
coefficients, block residuals and the residue slots that never feed negation.
The three-limb equality accepts exactly that domain. Since `2^253 < q < 2^254 <
2q`, two representatives of one residue differ by `0`, `q` or `-q`, and each
branch is checked as an integer relation below the native field size. Negation
by subtraction needs a canonical operand, so the imaginary inverse-residue
coefficients, which Frobenius conjugates, are decoded canonically. Unsafe
constructors (`from_limbs_unsafe`, struct literals for `BigNumParams`) and
handwritten providers do not acquire these guarantees.

The complete verifier binds the public-input MSM and all pairing obligations.
The residue inverse excludes zero; the scaling factor must lie in Fq6. The exact
Miller/Frobenius schedule, curve/subgroup checks, polynomial degrees, quotient
lengths, challenge domains and committed-before-challenge order are part of the
statement. Every round block must constrain its defining residual. An evaluator
or pairing-only helper is not a complete verifier, which is why none is exported
(`scripts/check-public-api.sh` checks this). The equations and exceptional-case
arguments are in [OPTIMISATIONS.md](OPTIMISATIONS.md).

A generated `FixedKey` provider is trusted code. Its trait does not certify
arbitrary handwritten tables, preprocessing or offsets. Runtime keys need both
structural validation and application authorization. Generic BigNum/BigCurve
custom-provider completeness remains a separate obligation; supported public
point negation and subtraction must preserve admitted bounded aliases.

The active runtime path uses `#[no_predicates]` helpers. Their required calls
must remain unconditional in the complete verifier, with internal predicates
and all defining relations preserved. A helper's standalone compilation does
not establish that its caller links every required check.

## Application and recursive boundaries

The finite outer point policy is intentional; it is not support for every
mathematically valid Groth16 infinity configuration. Intermediate cancellation
and unused infinity IC entries must not be rejected accidentally.

Authenticate the intended key/program and bind application effects to the
proved public inputs. A proof can have different bytes for the same statement;
proof-byte hashes alone do not prevent replay. A stateless verification helper
does not consume a nonce or authorize a caller-chosen beneficiary.

A recursive consumer authenticates its producer verification key, inner key and
statement. Backend verification must discharge the final pairing/PCS obligations.
Native execution, hints and local checks establish none of that deferred work.

## SP1 proofs

The SP1 entry points check what SP1's onchain verifier checks, nothing more.
For SP1 v5 that is the Groth16 statement over `[program vkey, SHA-256(public
values) masked to 253 bits]`. For SP1 v6 (`sp1::v6::verify`) the statement has
five inputs: the same two, then the exit code, the recursion verification-key
root and the proof nonce. The circuit fixes the exit code to 0 and the root to
`sp1::v6::VK_ROOT`, the root SP1 pins for circuit version v6.1.0 (generated
from SP1's `verifier_vks.bin`), as the onchain verifier rejects any other
value. The nonce is bound but not checked: it is chosen by whoever requested
the proof, and SP1 gives it no meaning. SP1's Rust verifier also accepts a
public-values digest computed with BLAKE3; the onchain verifier and these entry
points accept SHA-256 only. The verifier selector (the first four proof bytes)
is a host-side routing check: the circuit compiles in one key, so a proof for
another key fails the pairing check whatever its selector. The v6 key type is
crate-private, so `groth16::verify` cannot be called with it and hand-built
inputs that skip the exit-code and root pins.

No revocation: a circuit with a compiled-in SP1 key accepts proofs for that SP1
circuit version (v6.1.0 for `sp1::v6::verify`) until the application ships a
new circuit. The caller inherits the soundness of that circuit version and of
its trusted setup, and should follow SP1's security advisories.

The proof nonce is chosen by the prover (zeros by default); it is bound into
the statement but not checked. It must not serve as a nullifier or as replay
protection, and should be passed as a private witness. The program vkey is the
canonical field element of SP1's 32-byte vkey hash: the circuit takes a field
element, and the host package rejects values at or above the scalar modulus,
as the Solidity verifier does.

The caller must still pin the program vkey, bind and interpret the public
values, and provide replay protection.

## Validation limits

Test honest exceptional inputs separately from invalid supplied hints. An honest
unconstrained helper rejecting an input does not prove that forged witnesses are
constrained. Source bounds, relation-level negatives and composition checks have
different roles. Compilation, ACVM execution, backend constraint checking,
cryptographic proof verification and an Aztec transaction are distinct results.

Compiling some consumers needs `--skip-brillig-constraints-check`. This skips
automatic static hint-coverage analysis, not the ordinary arithmetic
constraints: the compiler's check rejects the BigNum quotient/borrow hint even
for Fq multiplication, although that hint feeds range-checked quotient limbs and
a constrained limb expression. Neither that analysis nor an honest proof
establishes absence of malicious alternate witnesses.

## Key preprocessing

Generated providers reject known degenerate verification-key relations and all-infinity
IC sets. These checks cannot detect a setup trapdoor retained by an adversary.
Applications still authenticate the intended circuit key; test vectors and generated
provider tables are not trust policy.
