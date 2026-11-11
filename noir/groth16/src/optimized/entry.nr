use super::fixed_key::FixedKey;
use g1::constrained_ops::to_bigcurve;
use noir_bn254_pairing::fp::fp_from_limbs_checked;
use noir_bn254_pairing::fp2::Fp2;
use noir_bn254_pairing::g1::{G1Affine, is_on_curve_g1_affine};
use noir_bn254_pairing::g2::{G2Affine, is_on_curve_g2_affine};

pub type RawProof = [[u128; 3]; 10];

fn fp2(real: [u128; 3], imaginary: [u128; 3]) -> Fp2 {
    Fp2 { c0: fp_from_limbs_checked(real), c1: fp_from_limbs_checked(imaginary) }
}

pub fn decode_finite_proof_and_validate_b(raw: RawProof) -> [G1Affine; 3] {
    let points = [
        G1Affine { x: fp_from_limbs_checked(raw[0]), y: fp_from_limbs_checked(raw[1]) },
        G1Affine { x: fp_from_limbs_checked(raw[6]), y: fp_from_limbs_checked(raw[7]) },
        G1Affine { x: fp_from_limbs_checked(raw[8]), y: fp_from_limbs_checked(raw[9]) },
    ];
    let b = G2Affine { x: fp2(raw[2], raw[3]), y: fp2(raw[4], raw[5]) };
    assert(!points[0].is_infinity(), "Groth16 A must be finite");
    assert(!points[1].is_infinity(), "Groth16 C must be finite");
    assert(!points[2].is_infinity(), "Groth16 input MSM must be finite");
    assert(!b.is_infinity(), "Groth16 B must be finite");
    assert(is_on_curve_g2_affine(b), "Invalid Groth16 G2 curve point");
    // The fixed terminal stage proves subgroup membership from the authenticated Miller point.
    points
}

pub fn validate_private_fixed_inputs<Key, let N: u32>(
    raw: RawProof,
    inputs: [Field; N],
    components: [[Field; 2]; N],
)
where
    Key: FixedKey<N>,
{
    let points = decode_finite_proof_and_validate_b(raw);
    let msm = super::fixed_key_glv::glv_fixed::<Key, N>(inputs, components);
    let expected = to_bigcurve(points[2]);
    assert(msm.is_infinity == expected.is_infinity, "Invalid Groth16 input MSM infinity");
    if !msm.is_infinity {
        assert(msm.x == expected.x, "Invalid Groth16 input MSM x");
        assert(msm.y == expected.y, "Invalid Groth16 input MSM y");
    }
    assert(is_on_curve_g1_affine(points[0]), "Invalid Groth16 A curve point");
    assert(is_on_curve_g1_affine(points[1]), "Invalid Groth16 C curve point");
}
