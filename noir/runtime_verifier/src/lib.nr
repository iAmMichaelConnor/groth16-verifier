//! Runtime-key Groth16 verification for BN254 (Circom/snarkjs keys and proofs).
//!
//! The verification key is a circuit input. [`verify`] checks a proof against
//! the supplied key and public inputs, with every constraint in the circuit,
//! and returns the canonical hash of that key ([`key_commitment`]). The
//! application must check that hash against a key it trusts, e.g. with
//! [`assert_authorized_key`]: a valid proof under a prover-chosen key proves
//! nothing.
pub use pairing::{Accumulators, BlockResiduals, Quotient, RawPairing, RawResidue};
pub use schema::{
    assert_authorized_key, input_commitment, key_commitment, RawVerificationKey, statement_id,
};
pub type RawProof = [[u128; 3]; 8];
pub type RawG1 = [[u128; 3]; 2];

/// Every prover-supplied witness of one runtime-key verification. All fields are
/// untrusted: the verifier constrains each of them against the key, the public
/// inputs and the proof. `magnitudes` and `negative` are the signed GLV
/// decomposition of each public input.
pub struct Hints<let N: u32> {
    pub claimed_l: RawG1,
    pub magnitudes: [[Field; 2]; N],
    pub negative: [[bool; 2]; N],
    pub residue: RawResidue,
    pub accumulators: Accumulators,
    pub quotient: Quotient,
    pub block_residuals: BlockResiduals,
}

/// Verifies a Groth16 proof for `inputs` against `key` and returns the
/// canonical key hash, which the caller must compare with a trusted value.
///
/// Every point, scalar, line and pairing constraint is in this circuit. A, B, C
/// and the input point L must be finite; IC points may be infinity if L is
/// finite. Fails (an unsatisfiable circuit) unless the proof verifies.
pub fn verify<let N: u32>(
    key: RawVerificationKey<N>,
    inputs: [Field; N],
    proof: RawProof,
    hints: Hints<N>,
) -> Field {
    let context = schema::pairing_context(key, inputs);
    checked_g1_private(
        key,
        inputs,
        proof,
        hints.claimed_l,
        hints.magnitudes,
        hints.negative,
    );
    checked_pairing(
        assemble(key, proof, hints.claimed_l),
        context,
        hints.residue,
        hints.accumulators,
        hints.quotient,
        hints.block_residuals,
    );
    context[1]
}

mod benchmarks;

// Private construction prevents an independent caller-supplied pairing key or
// context from diverging from the key/MSM checked above.
fn assemble<let N: u32>(
    key: RawVerificationKey<N>,
    proof: RawProof,
    claimed_l: RawG1,
) -> RawPairing {
    let mut raw = [[0; 3]; 24];
    for i in 0..8 {
        raw[i] = proof[i];
    }
    for i in 0..2 {
        raw[8 + i] = claimed_l[i];
        raw[10 + i] = key.alpha[i];
    }
    for i in 0..4 {
        raw[12 + i] = key.beta[i];
        raw[16 + i] = key.gamma[i];
        raw[20 + i] = key.delta[i];
    }
    raw
}

// These ordinary helpers are called unconditionally. no_predicates controls
// compiler inlining; it does not create private calls or acceptance boundaries.
#[no_predicates]
fn checked_g1_private<let N: u32>(
    key: RawVerificationKey<N>,
    inputs: [Field; N],
    proof: RawProof,
    claimed_l: RawG1,
    magnitudes: [[Field; 2]; N],
    negative: [[bool; 2]; N],
) {
    g1::validate_private(key, inputs, proof, claimed_l, magnitudes, negative);
}
#[no_predicates]
fn checked_pairing(
    raw: RawPairing,
    context: [Field; 3],
    residue: RawResidue,
    accumulators: Accumulators,
    quotient: Quotient,
    block_residuals: BlockResiduals,
) {
    pairing::verify(
        raw,
        context,
        residue,
        accumulators,
        quotient,
        block_residuals,
    );
}
