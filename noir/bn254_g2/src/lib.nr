//! BN254 G2 on the sextic twist y^2 = x^3 + 3/(9 + u) over Fq2: affine,
//! Jacobian and projective points, group arithmetic, Frobenius maps, subgroup
//! checks and the line evaluations used by Miller loops.
//!
//! An on-twist check does not imply subgroup membership; use
//! `g2::is_in_correct_subgroup_g2` (or the `_fast` variant) where it matters.
pub use bignum::BigNum;
pub use fields::{fp, fp2};
pub mod g2;
pub mod affine;

pub use g2::{G2Affine, G2Jac, G2Proj, LineEvaluation, LineScheduleRaw};

mod benchmarks;
