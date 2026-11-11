use bignum::BigNum;
use bignum::BN254_Fq;

/// Base field Fp for BN254 (Fq).
pub type Fp = BN254_Fq;

/// BN254 parameter x for the optimal Ate pairing loop.
pub fn seed_x0() -> u128 {
    4965661367192848881
}

/// Field zero.
pub fn fp_zero() -> Fp {
    Fp::from_limbs([0x0, 0x0, 0x0])
}

/// Field one.
pub fn fp_one() -> Fp {
    Fp::from_limbs([0x1, 0x0, 0x0])
}

/// Field constant 2.
pub fn fp_two() -> Fp {
    Fp::from_limbs([0x2, 0x0, 0x0])
}

/// Field constant 3 (curve b parameter).
pub fn fp_three() -> Fp {
    Fp::from_limbs([0x3, 0x0, 0x0])
}

/// Field constant 4.
pub fn fp_four() -> Fp {
    Fp::from_limbs([0x4, 0x0, 0x0])
}

/// Field constant 8.
pub fn fp_eight() -> Fp {
    Fp::from_limbs([0x8, 0x0, 0x0])
}

/// Field constant 9 (quadratic non-residue seed).
pub fn fp_nine() -> Fp {
    Fp::from_limbs([0x9, 0x0, 0x0])
}

/// Assert each limb fits in 120 bits (canonical limb size).
pub fn assert_fp_limbs_in_range(limbs: [u128; 3]) {
    let max: u128 = 1 << 120;
    assert(limbs[0] < max);
    assert(limbs[1] < max);
    assert(limbs[2] < max);
}

/// Build an Fp element from limbs with range checks.
pub fn fp_from_limbs_checked(limbs: [u128; 3]) -> Fp {
    // BigNum v0.11 from_limbs already enforces 120/120/14-bit bounds.
    let value = Fp::from_limbs(limbs);
    value.validate_in_field();
    value
}

/// BN254 G1 generator x-coordinate.
pub fn g1_generator_x() -> Fp {
    fp_one()
}

/// BN254 G1 generator y-coordinate.
pub fn g1_generator_y() -> Fp {
    fp_two()
}

/// Curve parameter b for y^2 = x^3 + b over Fp.
pub fn curve_b() -> Fp {
    fp_three()
}
/// Little-endian signed NAF digits of 6*x+2 for the BN254 optimal Ate loop.
/// Curve data shared by fixed and runtime schedules; never a witness input.
pub fn miller_loop_digits() -> [i8; 66] {
    [
        0i8, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0,
        0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
        -1, 0, 0, 0, 1, 0, -1, 0, 1,
    ]
}
