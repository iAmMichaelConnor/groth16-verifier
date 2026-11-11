// Typechecks of the runtime-key entry points for a generic input count, as an
// external application would call them. No claim that any input verifies.
use schema::RawVerificationKey;
use verifier::Hints;

pub fn verify<let N: u32>(
    key: RawVerificationKey<N>,
    inputs: [Field; N],
    proof: [[u128; 3]; 8],
    hints: Hints<N>,
) -> Field {
    verifier::verify(key, inputs, proof, hints)
}

// The hint shapes are part of the API: a change to them breaks callers.
pub fn hints<let N: u32>(
    claimed_l: [[u128; 3]; 2],
    magnitudes: [[Field; 2]; N],
    negative: [[bool; 2]; N],
    residue: [[u128; 3]; 36],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 94],
    block_residuals: [[u128; 3]; 9],
) -> Hints<N> {
    Hints { claimed_l, magnitudes, negative, residue, accumulators, quotient, block_residuals }
}
