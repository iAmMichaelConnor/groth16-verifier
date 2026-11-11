// Benchmark entry points: the complete runtime-key verifier for one and two
// public inputs. `nargo export` compiles each to its own program for the gates
// report.
use crate::{Hints, RawProof, RawVerificationKey};

#[export]
fn runtime_verify_1(
    key: RawVerificationKey<1>,
    inputs: [Field; 1],
    proof: RawProof,
    hints: Hints<1>,
) -> Field {
    crate::verify(key, inputs, proof, hints)
}

#[export]
fn runtime_verify_2(
    key: RawVerificationKey<2>,
    inputs: [Field; 2],
    proof: RawProof,
    hints: Hints<2>,
) -> Field {
    crate::verify(key, inputs, proof, hints)
}
