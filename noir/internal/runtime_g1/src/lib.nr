//! Complete runtime-key BN254 G1 validation and MSM.
//! No point-offset assumptions. Infinity is exactly the raw encoding (0,0).
//! Pairing entry points impose their separate finite-point policy.
use bigcurve::{BigCurve, BN254};
use bignum::{BigNum, BN254_Fq as Fp};
use fields::fp::fp_from_limbs_checked;
use schema::RawVerificationKey;

pub type RawG1 = [[u128; 3]; 2];
global LAMBDA: Field =
    21888242871839275217838484774961031246154997185409878258781734729429964517155;

/// Canonical coordinate decoding only. This is not a membership assertion.
fn decode_coordinates(raw: RawG1) -> BN254 {
    let x = fp_from_limbs_checked(raw[0]);
    let y = fp_from_limbs_checked(raw[1]);
    let infinity = (x == Fp::zero()) & (y == Fp::zero());
    BN254 { x, y, is_infinity: infinity }
}

/// BN254 G1 has prime order: finite curve membership implies subgroup membership.
pub fn decode_point(raw: RawG1) -> BN254 {
    let point = decode_coordinates(raw);
    point.validate_on_curve();
    point
}

fn signed(point: BN254, negative: bool) -> BN254 {
    if point.is_infinity {
        BN254::point_at_infinity()
    } else if negative {
        -point
    } else {
        point
    }
}

fn endomorphism(point: BN254) -> BN254 {
    let beta = Fp::from_limbs([
        742632800561498340512714380273319240,
        407329191355487526249269639571615938,
        12388,
    ]);
    BN254 { x: point.x * beta, y: point.y, is_infinity: point.is_infinity }
}

unconstrained fn digit_hint(magnitude: Field) -> [u8; 63] {
    let value = magnitude as u128;
    let mut out = [0; 63];
    for i in 0..63 {
        out[i] = ((value >> ((i as u128) * 2)) & 3) as u8;
    }
    out
}

fn checked_digits(magnitude: Field) -> [u8; 63] {
    magnitude.assert_max_bit_size::<126>();
    // Safety: exact63 radix4 digits reconstruct an integer below2^126<Fr.
    // Every supplied digit retains an explicit2-bit bound.
    let digits = unsafe { digit_hint(magnitude) };
    let mut value: Field = 0;
    let mut factor: Field = 1;
    for i in 0..63 {
        (digits[i] as Field).assert_max_bit_size::<2>();
        value += (digits[i] as Field) * factor;
        factor *= 4;
    }
    assert(value == magnitude, "Invalid GLV digit decomposition");
    digits
}

/// Complete runtime MSM with signed joint radix4 GLV tables.
/// All126 magnitude bits are consumed in63 windows. Infinity/cancellation is
/// handled by complete group operations, including every table cross-add.
pub fn private_msm<let N: u32>(
    ic: [RawG1; N + 1],
    inputs: [Field; N],
    magnitudes: [[Field; 2]; N],
    negative: [[bool; 2]; N],
) -> BN254 {
    let infinity = BN254::point_at_infinity();
    let mut tables = [[infinity; 16]; N];
    let mut digits = [[[0; 63]; 2]; N];
    let initial = decode_point(ic[0]);
    for i in 0..N {
        let point = signed(decode_point(ic[i + 1]), negative[i][0]);
        digits[i][0] = checked_digits(magnitudes[i][0]);
        digits[i][1] = checked_digits(magnitudes[i][1]);
        let a = if negative[i][0] {
            -magnitudes[i][0]
        } else {
            magnitudes[i][0]
        };
        let b = if negative[i][1] {
            -magnitudes[i][1]
        } else {
            magnitudes[i][1]
        };
        assert(a + LAMBDA * b == inputs[i], "Invalid signed GLV decomposition");
        let mut multiples = [infinity; 4];
        let mut phi_multiples = [infinity; 4];
        multiples[1] = point;
        for j in 2..4 {
            multiples[j] = multiples[j - 1] + point;
        }
        let flip_phi = negative[i][0] != negative[i][1];
        for j in 1..4 {
            phi_multiples[j] = signed(endomorphism(multiples[j]), flip_phi);
        }
        for b in 0..4 {
            for a in 0..4 {
                // Skip only algebraically exact identity additions. All nine
                // nontrivial cross-adds use the unchanged complete formula.
                tables[i][4 * b + a] = if a == 0 {
                    phi_multiples[b]
                } else if b == 0 {
                    multiples[a]
                } else {
                    multiples[a] + phi_multiples[b]
                };
            }
        }
    }
    let mut result = infinity;
    for window in 0..63 {
        if window != 0 {
            for _ in 0..2 {
                result = result + result;
            }
        }
        let index = 62 - window;
        for i in 0..N {
            // Each digit is in0..3, so this exactu32 expression is in0..15.
            let joint_index = (digits[i][0][index] as u32) + 4 * (digits[i][1][index] as u32);
            result = result + tables[i][joint_index];
        }
    }
    result + initial
}

pub fn assert_private_msm<let N: u32>(
    ic: [RawG1; N + 1],
    inputs: [Field; N],
    claimed: RawG1,
    magnitudes: [[Field; 2]; N],
    negative: [[bool; 2]; N],
) {
    let actual = private_msm(ic, inputs, magnitudes, negative);
    let expected = decode_point(claimed);
    assert(actual == expected, "Incorrect runtime G1 MSM");
}

/// Public proof order is A.x,A.y,B.x.real,B.x.imag,B.y.real,B.y.imag,C.x,C.y.
pub fn validate_private<let N: u32>(
    key: RawVerificationKey<N>,
    inputs: [Field; N],
    proof: [[u128; 3]; 8],
    claimed: RawG1,
    magnitudes: [[Field; 2]; N],
    negative: [[bool; 2]; N],
) {
    let _alpha = decode_point(key.alpha);
    let _a = decode_point([proof[0], proof[1]]);
    let _c = decode_point([proof[6], proof[7]]);
    assert_private_msm(key.ic, inputs, claimed, magnitudes, negative);
}

mod tests {
    use super::{assert_private_msm, decode_point, private_msm, RawG1};

    global INFINITY: RawG1 = [[0, 0, 0], [0, 0, 0]];
    global G: RawG1 = [[1, 0, 0], [2, 0, 0]];
    // 2G for the generator G = (1, 2) of y^2 = x^3 + 3.
    global TWO_G: RawG1 = [
        [0x7816a916871ca8d3c208c16d87cfd3, 0x44e72e131a029b85045b68181585d9, 0x306],
        [0xa6a449e3538fc7ff3ebf7a5a18a2c4, 0x738c0e0a7c92e7845f96b2ae9c0a68, 0x15ed],
    ];
    // q - 2, the y coordinate of -G.
    global NEG_G: RawG1 =
        [[1, 0, 0], [0x816a916871ca8d3c208c16d87cfd45, 0x4e72e131a029b85045b68181585d97, 0x3064]];

    // A small input s has the decomposition s = s + LAMBDA * 0.
    #[test]
    fn msm_matches_known_multiples() {
        // 0 + [2]G
        assert_private_msm([INFINITY, G], [2], TWO_G, [[2, 0]], [[false, false]]);
        // G + [1]G
        assert_private_msm([G, G], [1], TWO_G, [[1, 0]], [[false, false]]);
        // G + [-1]G = infinity, using the negative sign flag
        assert(private_msm([G, G], [-1], [[1, 0]], [[true, false]]).is_infinity);
        // 0 + [-1]G = -G
        assert_private_msm([INFINITY, G], [-1], NEG_G, [[1, 0]], [[true, false]]);
        // A zero input leaves IC0; an unused IC1 at infinity is accepted.
        assert_private_msm([G, INFINITY], [0], G, [[0, 0]], [[false, false]]);
        // No public inputs: the result is IC0.
        assert_private_msm([TWO_G], [], TWO_G, [], []);
    }

    #[test(should_fail_with = "Invalid signed GLV decomposition")]
    fn msm_rejects_a_decomposition_of_another_scalar() {
        assert_private_msm([INFINITY, G], [2], TWO_G, [[1, 0]], [[false, false]]);
    }

    #[test(should_fail_with = "Incorrect runtime G1 MSM")]
    fn msm_rejects_a_wrong_claimed_result() {
        assert_private_msm([INFINITY, G], [2], G, [[2, 0]], [[false, false]]);
    }

    // The curve equation is one fused non-native relation. Its unconstrained
    // hint helper rejects the off-curve point first, so this pins hint
    // generation, not the constraint.
    #[test(should_fail_with = "Quadratic expression hint has a nonzero remainder")]
    fn decode_rejects_an_off_curve_point() {
        let _ = decode_point([[1, 0, 0], [3, 0, 0]]);
    }
}
