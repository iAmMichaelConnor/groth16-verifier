//! BN254 G1 (y^2 = x^3 + 3 over Fq): affine and Jacobian points, on-curve
//! checks and group arithmetic over `bn254_fields`. `constrained_ops` adds a
//! constrained multi-scalar multiplication through the BigCurve representation.
//!
//! The affine point (0, 0) encodes infinity. No function checks that its inputs
//! are on the curve; use `g1::is_on_curve_g1_affine` on untrusted points.
pub use bignum::BigNum;
pub use fields::fp;
pub mod g1;
pub mod constrained_ops;

pub use g1::{G1Affine, G1Jac};

mod benchmarks;
