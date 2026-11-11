// Benchmark entry point: the complete fixed-key verifier under an ordinary
// Circom key with one public input (the multiplier circuit of
// `fixtures/multiplier`). `nargo export` compiles it to its own program for
// the gates report.
use crate::key1::Key1;

#[export]
fn groth16_verify_1(
    inputs: [Field; 1],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 1],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) {
    groth16::verify::<Key1, 1>(
        inputs,
        raw,
        residue,
        components,
        accumulators,
        quotient,
        block_residuals,
    );
}
