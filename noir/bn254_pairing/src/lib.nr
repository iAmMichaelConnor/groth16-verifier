//! The optimal ate pairing on BN254: `pairing`, `pairing_multi`, and their
//! parts `miller_loop` and `final_exponentiation`, computed directly in
//! constrained Fq12 arithmetic.
//!
//! This computes the pairing value itself, including the final
//! exponentiation. The Groth16 verifiers in this repository do not call it:
//! they check the pairing equation with a hinted certificate
//! (`bn254_pairing_checks`) instead. Inputs are not checked to be in G1 or G2.
pub use bignum::BigNum;
pub use curve_g1::g1;
pub use curve_g2::g2;
pub use fields::{fp, fp12, fp2, fp6};
// Private module: only the functions re-exported below are public API.
mod pairing;
pub use pairing::{final_exponentiation, miller_loop, pairing, pairing_multi};

mod tests;
