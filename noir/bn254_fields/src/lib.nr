//! BN254 base field Fq and its extension tower Fq2, Fq6 and Fq12 (the tower
//! used by the BN254 pairing: Fq2 = Fq[u]/(u^2 + 1), Fq6 = Fq2[v]/(v^3 - (9 + u)),
//! Fq12 = Fq6[w]/(w^2 - v)), as constrained non-native arithmetic.
//!
//! `Fp` is a three-limb BigNum (120/120/14-bit limbs). `fp::fp_from_limbs_checked`
//! range-checks and canonicalises limbs from outside the circuit; arithmetic
//! results are reduced only as far as the BigNum relations require, so call
//! `validate_in_field` before exposing a value as canonical.
pub mod fp;
pub mod fp2;
pub mod fp6;
pub mod fp12;
pub use bignum::BigNum;

// Canonical field identities shared by every public verifier and primitive.
pub use fp::Fp;
pub use fp12::Fp12;
pub use fp2::Fp2;
pub use fp6::Fp6;

mod tests;
mod benchmarks;
