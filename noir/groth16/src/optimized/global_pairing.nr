use super::fixed_key::FixedKey;
use fields::BigNum;
use fields::fp::{Fp, fp_from_limbs_checked};
use g2::g2::{frobenius_g2, frobenius_square_g2, G2Affine, neg_g2_affine};
use pairing_checks::certificate::{assert_global_relations_68, decode_residue};
use pairing_checks::polynomial::{
    coefficients, dot, fp12, fp2, line_value, line_weights, powers, residue_frobenius_evaluations,
    tower_weights, twelve,
};
// Private geometry is valid only for the exact checked-origin schedule below.
// Its nonzero-denominator argument is noir/groth16/tests/check_schedule_denominators.py;
// the generic helpers in pairing_checks::lines remain guarded.
mod schedule_geometry;
use pairing_checks::lines::normalize;
use pairing_checks::transcript::transcript_hash;
use schedule_geometry::{add_step, double_step, line_compute, line_with_endpoint};

// Mathematical basis: Novakovic and Eagen, On Proving Pairings (2024),
// https://eprint.iacr.org/2024/640 . The comments below state the algebra and
// limits this code relies on.
// Write q for BN254's base prime and r for its scalar prime. Noir Field is Fr;
// Fp below is a non-native Fq implemented with three checked 120/120/14-bit limbs.
// The checked product is e(A,B)e(C,-delta)e(L,-gamma)e(-alpha,beta)=1.
// This fixed-key specialization precomputes delta/gamma lines and the alpha/beta
// contribution. The caller must use the same fixed key when constraining L.
global DOMAIN: Field = 1587639913047856220144874247109043781673300224;
/// Complete pairing equations. Crate-internal: the caller MUST first run
/// entry::validate_*_fixed_inputs (finite A, C, L and B, B on the twist, A and C
/// on G1, and L = IC[0] + sum inputs[i] * IC[i+1] for the same Key). This
/// function proves B is in G2. Without the L binding the relation alone is
/// forgeable: A = C = L = alpha, B = beta + gamma + delta satisfies it.
pub fn verify_fixed<Key, let N: u32>(
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
)
where
    Key: FixedKey<N>,
{
    let proof = raw.map(fp_from_limbs_checked);
    let res = decode_residue(residue);
    let accs = accumulators.map(|a| a.map(fp_from_limbs_bounded));
    let q = quotient.map(fp_from_limbs_bounded);
    let residuals = block_residuals.map(fp_from_limbs_bounded);
    // The witness is (c,c_inverse,w), each in Fq12. The final six tower coefficients
    // of w must vanish, restricting it to Fq6. For n=6*x+2 and
    // lambda=n+q-q^2+q^3, the complete relation is f*t_preimage*w=c^lambda.
    // Because r divides lambda and (q^6-1) divides (q^12-1)/r, this implies the
    // pairing equation after final exponentiation, without computing that exponent.
    // Subfield scaling is required for completeness: gcd(lambda,q^12-1)=3r,
    // whereas gcd(lambda,q^6+1)=r. Arbitrary Fq12 scaling would be unsound.
    for j in 30..36 {
        assert(res[j] == Fp::from(0), "Invalid Groth16 residue subfield");
    }
    // Fiat-Shamir order matters. Bind raw proof/L, residue, and all 66 intermediate
    // extension elements before rho. Then bind all 76 quotient coefficients before z.
    // Do not replace either hash with a prover-supplied challenge. All coefficient
    // limbs must be bounded before the injective packing used by transcript_hash.
    // Geometry is constrained from the committed B; it is not a free post-rho hint.
    let mut transcript_coeffs = [[0; 3]; 838];
    for i in 0..10 {
        transcript_coeffs[i] = raw[i];
    }
    for i in 0..36 {
        transcript_coeffs[10 + i] = residue[i];
    }
    for i in 0..66 {
        for j in 0..12 {
            transcript_coeffs[46 + 12 * i + j] = accumulators[i][j];
        }
    }
    let rho_field = transcript_hash([DOMAIN, 68], transcript_coeffs);
    assert(rho_field != 0);
    let rho = Fp::from(rho_field);
    let powers = powers(Fp::from(transcript_hash([DOMAIN + 1, rho_field], quotient)));
    // Use Fq[X]/M(X), M=X^12-18X^6+82, for extension-field identities.
    // Each source relation is checked at z using its quotient by M. The largest
    // fixed-key relation degree is 87 (regular rounds), so Q has at most 76 coefficients.
    // These are randomized polynomial checks, under the stated hash assumptions,
    // not exact coefficient equality for an arbitrary prover-chosen z.
    let weights = tower_weights(powers);
    let lw = [
        line_weights(proof[0], proof[1], powers),
        line_weights(proof[6], proof[7], powers),
        line_weights(proof[8], proof[9], powers),
    ];
    let c = dot(twelve(res, 0), weights);
    let ci = dot(twelve(res, 12), weights);
    let evals = accs.map(|a| dot(a, weights));
    let mut products = [Fp::from(0); 68];
    let mut outputs = products;
    // All 68 identities: inverse0, prefix intermediate1, remaining prefix2,
    // rounds3..65, terminal line product66, final residue relation67.
    // The inverse relation is what rules out c=0; a terminal zero-product check alone
    // would not suffice. A finite set of passing witnesses is not a soundness proof.
    products[0] = c * ci;
    outputs[0] = Fp::from(1);
    let b = G2Affine { x: fp2(proof[2], proof[3]), y: fp2(proof[4], proof[5]) };
    let delta = Key::delta_lines();
    let gamma = Key::gamma_lines();
    let (point, d) = double_step(b);
    let doubles = [d, normalize(delta.initial_double), normalize(gamma.initial_double)];
    let mut product = ci * ci;
    for k in 0..3 {
        product = product * line_value(doubles[k], lw[k]);
    }
    products[1] = product;
    outputs[1] = evals[0];
    product = evals[0] * evals[0];
    let (_, l) = line_compute(point, neg_g2_affine(b));
    let (point, a) = add_step(point, b);
    let lines = [l, normalize(delta.pre_loop_line), normalize(gamma.pre_loop_line)];
    let adds = [a, normalize(delta.pre_loop_add), normalize(gamma.pre_loop_add)];
    for k in 0..3 {
        product = product * line_value(lines[k], lw[k]);
        product = product * line_value(adds[k], lw[k]);
    }
    product = product * c; // The fixed BN254 NAF prefix digit is -1.
    products[2] = product;
    outputs[2] = evals[1];

    let digits = fields::fp::miller_loop_digits();
    let mut point = point;
    let mut prev = evals[1];
    let bn = neg_g2_affine(b);
    for i in 0..63 {
        let idx = i;
        let digit = digits[62 - idx];
        let (next, d) = double_step(point);
        point = next;
        let doubles = [d, normalize(delta.loop_doubles[idx]), normalize(gamma.loop_doubles[idx])];
        let mut product = prev * prev;
        for k in 0..3 {
            product = product * line_value(doubles[k], lw[k]);
        }
        if digit != 0 {
            let (next, a) = add_step(point, if digit == 1 { b } else { bn });
            point = next;
            let adds = [
                a,
                if digit == 1 {
                    normalize(delta.loop_adds_pos[idx])
                } else {
                    normalize(delta.loop_adds_neg[idx])
                },
                if digit == 1 {
                    normalize(gamma.loop_adds_pos[idx])
                } else {
                    normalize(gamma.loop_adds_neg[idx])
                },
            ];
            for k in 0..3 {
                product = product * line_value(adds[k], lw[k]);
            }
            product = product * (if digit == 1 { ci } else { c });
        }
        products[i + 3] = product;
        outputs[i + 3] = evals[i + 2];
        prev = evals[i + 2];
    }

    // frobenius_square_g2 returns -psi^2, including its y sign. The endpoint checks
    // [6*x+2]B+psi(B)-psi^2(B)=-psi^3(B), not just a line through two points.
    // On the full twist, the norm gcd of this endomorphism with the group order is r.
    // Together with checked finite on-curve B and exact preceding steps, this proves
    // B is in the prime-order subgroup. Do not assume subgroup membership earlier
    // to justify exceptional-denominator avoidance; that would be circular.
    let delta = Key::delta_lines();
    let gamma = Key::gamma_lines();
    let (point, a) = add_step(point, frobenius_g2(b));
    let q2 = frobenius_square_g2(b);
    let l = line_with_endpoint(point, q2, frobenius_g2(q2));
    let adds = [a, normalize(delta.final_add), normalize(gamma.final_add)];
    let lines = [l, normalize(delta.final_line), normalize(gamma.final_line)];
    let mut product = evals[64];
    for k in 0..3 {
        product = product * line_value(adds[k], lw[k]);
        product = product * line_value(lines[k], lw[k]);
    }
    products[66] = product;
    outputs[66] = evals[65];
    product = evals[65];
    let c = fp12(twelve(res, 0));
    let ci = fp12(twelve(res, 12));
    product = product * dot(coefficients(Key::t_preimage()), weights);
    product = product * dot(twelve(res, 24), weights);
    let (first, second, third) = residue_frobenius_evaluations(c, ci, weights);
    product = product * first;
    product = product * second;
    product = product * third;

    products[67] = product;
    outputs[67] = Fp::from(1);
    // Factor the weights, not the obligations. Block b constrains
    // R_b=sum_j rho^j*(products[8*b+j]-outputs[8*b+j]); the final equation multiplies
    // each R_b by (rho^8)^b. Thus every original rho^i weight appears exactly once.
    // The last block contains indices 64, 65, 66 and 67. These blocks are ordinary equations
    // inside ONE circuit, with no separate proofs, private calls or state handoff.
    // Residuals may be supplied after challenges because their full equations bind
    // them; accepting arbitrary residuals after checking only their sum is unsound.
    assert_global_relations_68(products, outputs, rho, q, powers, residuals);
}

// All three raw limbs remain range checked. Accumulator and quotient coefficients
// enter the injective transcript encoding before their respective challenge.
// Internal block residuals are not hashed; exact modular equations bind them.
// No accumulator or residual is returned across a state/API boundary here.
fn fp_from_limbs_bounded(limbs: [u128; 3]) -> Fp {
    Fp::from_limbs(limbs)
}
