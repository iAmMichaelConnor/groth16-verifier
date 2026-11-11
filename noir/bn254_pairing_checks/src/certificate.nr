//! Shared exact relations for the existing 68-identity BN254 certificates.
//! Callers retain their distinct transcript domains, curve checks and schedules.
use crate::polynomial::quotient_value;
use bignum::bignum::evaluate_quadratic_expression;
use fields::BigNum;
use fields::fp::{Fp, fp_from_limbs_checked};

/// Exactly 68 relations in eight-term blocks. The final block contains four
/// relations; zero padding preserves the reviewed 16-product expression.
/// Every residual is checked before the ten-product terminal equation.
/// Q is a compile-time coefficient count; only the reviewed fixed/runtime
/// shapes (76/94) are supported. This helper does not construct a transcript.
// Let D_i=products[i]-outputs[i]. Each block enforces
// R_b=sum_{j<8,8*b+j<68} rho^j D_(8*b+j), then the tail enforces
// Q(z)*(z^12-18*z^6+82)=sum_{b<9} rho^(8*b) R_b.
// Thus all 68 relations have exactly weight rho^i; the final block has
// four live slots. Checking only the tail would leave free compensating R_b.
// Caller must bind relation witnesses before rho, quotient coefficients before
// z, and supply powers[k]=z^k in Fq. This helper does not establish that order.
// Fixed degree<=87 gives 76 coefficients; runtime degree<=105 gives 94.
// Q is compile-time, not a prover-selected mode. Preserve the 16-product blocks
// and 10-product tail when using the reviewed <=32-product carry specialization.
// Pairing/certificate basis: https://eprint.iacr.org/2024/640
pub fn assert_global_relations_68<let Q: u32>(
    products: [Fp; 68],
    outputs: [Fp; 68],
    rho: Fp,
    q: [Fp; Q],
    powers: [Fp; 17],
    residuals: [Fp; 9],
) {
    assert((Q == 76) | (Q == 94), "Unsupported global quotient shape");
    let mut rho_powers = [Fp::from(1); 8];
    for i in 1..8 {
        rho_powers[i] = rho_powers[i - 1] * rho;
    }
    let rho8 = rho_powers[7] * rho;
    let mut scales = [Fp::from(1); 9];
    for j in 1..9 {
        scales[j] = scales[j - 1] * rho8;
    }
    for block in 0..9 {
        let mut lhs = [[Fp::from(0)]; 16];
        let mut rhs = lhs;
        let mut signs = [[false]; 16];
        for j in 0..8 {
            let i = 8 * block + j;
            if i < 68 {
                lhs[2 * j] = [rho_powers[j]];
                rhs[2 * j] = [products[i]];
                lhs[2 * j + 1] = [rho_powers[j]];
                rhs[2 * j + 1] = [outputs[i]];
                signs[2 * j + 1] = [true];
            }
        }
        evaluate_quadratic_expression(lhs, signs, rhs, [[false]; 16], [residuals[block]], [true]);
    }
    let qz = quotient_value(q, powers);
    let modulus = powers[12] - Fp::from(18) * powers[6] + Fp::from(82);
    // Ten products, each one-by-one, ADD_N=1: the reviewed <=32-product narrow tail applies.
    let mut lhs = [[Fp::from(0)]; 10];
    let mut rhs = lhs;
    let mut signs = [[false]; 10];
    lhs[0] = [qz];
    rhs[0] = [modulus];
    for j in 0..9 {
        lhs[j + 1] = [scales[j]];
        rhs[j + 1] = [residuals[j]];
        signs[j + 1] = [true];
    }
    evaluate_quadratic_expression(lhs, signs, rhs, [[false]; 10], [Fp::from(0)], [false]);
}

// Internal residue representatives only. c uses Frobenius^2 without conjugation;
// ci real components pass through multiplication, but its imaginary components
// feed BigNum negation and MUST remain canonical. Upper w is strict and zero.
// All36 raw encodings are range-bounded and committed before rho. The inverse,
// Fq6 restriction and terminal equations remain unchanged.
// Layout: c[0..12], ci[12..24], w[24..36]. Only imaginary ci slots
// 13,15,17,19,21,23 feed canonical-only negation; real ci slots stay bounded.
// Slots 30..35 remain strict and the caller separately enforces zero (w in Fq6).
// c*ci=1 is checked elsewhere. Decoding alone neither proves inverseness nor
// the residue equation, and canonicalizing every slot would narrow this API.
pub fn decode_residue(raw: [[u128; 3]; 36]) -> [Fp; 36] {
    let mut values = [Fp::from(0); 36];
    for i in 0..36 {
        values[i] = if (i < 12) | ((i >= 12) & (i < 24) & (i % 2 == 0)) | ((i >= 24) & (i < 30)) {
            Fp::from_limbs(raw[i])
        } else {
            fp_from_limbs_checked(raw[i])
        };
    }
    values
}
