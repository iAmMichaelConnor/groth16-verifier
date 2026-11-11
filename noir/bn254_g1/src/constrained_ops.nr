//! Ordinary constrained BN254 G1 adapter. No experimental backend required.
use crate::g1::G1Affine;
pub use bigcurve::{BigCurve, BN254, BN254Scalar};

/// Representation conversion only; it does not assert curve membership.
/// Untrusted points must be validated by the caller before use in BigCurve.
pub fn to_bigcurve(point: G1Affine) -> BN254 {
    BN254 { x: point.x, y: point.y, is_infinity: point.is_infinity() }
}

/// Constrained MSM plus constant points; caller supplies valid G1 points.
/// Preserves the complete BigCurve output including its infinity flag.
pub fn evaluate_linear_expression<let N: u32, let M: u32>(
    points: [G1Affine; N],
    scalars: [Field; N],
    constants: [G1Affine; M],
) -> BN254 {
    BN254::evaluate_linear_expression(
        points.map(to_bigcurve),
        scalars.map(|s| BN254Scalar::from(s)),
        constants.map(to_bigcurve),
    )
}
