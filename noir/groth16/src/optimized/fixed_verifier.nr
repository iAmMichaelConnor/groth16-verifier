//! Complete fixed-key verification with compile-time public-input count.
//! Key is trusted code selected when compiling; there is no caller-supplied VK.
use super::fixed_key::FixedKey;

/// Verifies a Groth16 proof for `inputs` against the compiled key `Key`.
///
/// `raw` holds the proof points A, B and C and the input point L as checked
/// 120/120/14-bit Fq limbs; the other arguments are host-computed hints, all
/// untrusted and constrained here. A, B, C and L must be finite. Fails (an
/// unsatisfiable circuit) unless the proof verifies.
pub fn verify<Key, let N: u32>(
    inputs: [Field; N],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; N],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
)
where
    Key: FixedKey<N>,
{
    super::entry::validate_private_fixed_inputs::<Key, N>(raw, inputs, components);
    super::global_pairing::verify_fixed::<Key, N>(
        raw,
        residue,
        accumulators,
        quotient,
        block_residuals,
    );
}
