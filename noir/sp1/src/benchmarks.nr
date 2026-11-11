// Benchmark entry points: the complete fixed-key verifier under the SP1 v5 key
// (two public inputs) and under the SP1 v6 key (five public inputs). They
// exclude the SHA-256 of the public values that `sp1_public_inputs` and
// `v6::verify` add. `nargo export` compiles each to its own program for the
// gates report.
use crate::Sp1Key;
use crate::v6::Sp1V6Key;

#[export]
fn sp1_verify(
    inputs: [Field; 2],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 2],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) {
    groth16::verify::<Sp1Key, 2>(
        inputs,
        raw,
        residue,
        components,
        accumulators,
        quotient,
        block_residuals,
    );
}

// Not a verifier: inputs[2] must be 0 and inputs[3] VK_ROOT, which
// `v6::verify` fixes. It takes free inputs only to exclude the SHA-256, as
// `sp1_verify` does, and stays crate-private with the key it uses.
#[export]
fn sp1_v6_verify(
    inputs: [Field; 5],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 5],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) {
    groth16::verify::<Sp1V6Key, 5>(
        inputs,
        raw,
        residue,
        components,
        accumulators,
        quotient,
        block_residuals,
    );
}
