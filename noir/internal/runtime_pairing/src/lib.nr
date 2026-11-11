//! Runtime-key four-pair Groth16 equation using affine lines and one global
//! polynomial certificate. This is a pairing component, not an authorized
//! verifier by itself: the caller must validate G1 membership, bind the input
//! MSM, and compute context from the canonical key and actual public inputs.
use fields::BigNum;
use fields::fp::{Fp, fp_from_limbs_checked};
use g1::g1::G1Affine;
use g2::g2::{frobenius_g2, frobenius_square_g2, G2Affine, is_on_curve_g2_affine, neg_g2_affine};
use std::ops::Neg;
// Private exact Miller schedule only; all four origins are checked finite/on-curve.
mod schedule_geometry;
use pairing_checks::certificate::{assert_global_relations_68, decode_residue};
use pairing_checks::polynomial::{
    dot, fp12, fp2, line_value, line_weights, powers, residue_frobenius_evaluations, tower_weights,
    twelve,
};
use pairing_checks::transcript::transcript_hash;
use schedule_geometry::{add_step, double_step, line_compute, line_with_endpoint};

pub type RawPairing = [[u128; 3]; 24];
pub type RawResidue = [[u128; 3]; 36];
// Versioned68-identity certificate: prefix H, initial,63 rounds, terminal T.
// Both H and T are bound before rho; Q94 before z. Maximum round degree105.
pub type Accumulators = [[[u128; 3]; 12]; 66];
pub type Quotient = [[u128; 3]; 94];
pub type BlockResiduals = [[u128; 3]; 9];
global DOMAIN: Field = 406435817742925408890100530792079663938818945280;

/// raw = Axy || Bx0,x1,y0,y1 || Cxy || Lxy || alpha_xy ||
///       beta_x0,x1,y0,y1 || gamma_x0,x1,y0,y1 || delta_x0,x1,y0,y1.
/// The key G2 points use standard non-negated coordinates.
/// context = [number_of_inputs, key_commitment, input_commitment], computed
/// by the complete wrapper, never trusted from an application caller.
///
/// Pairing points A,C,L,alpha and all four G2 points must be finite.
/// This function checks canonical point coordinates, finite policy, G2 curve
/// membership and all four G2 subgroups. G1 membership and the input MSM are
/// obligations of the complete wrapper.
pub fn verify(
    raw: RawPairing,
    context: [Field; 3],
    residue: RawResidue,
    accumulators: Accumulators,
    quotient: Quotient,
    block_residuals: BlockResiduals,
) {
    let decoded = raw.map(fp_from_limbs_checked);
    let res = decode_residue(residue);
    let accs = accumulators.map(|a| a.map(bounded));
    let q = quotient.map(bounded);
    let residuals = block_residuals.map(bounded);
    for j in 30..36 {
        assert(res[j] == Fp::from(0), "Runtime Groth16 residue must be in Fq6");
    }
    let g1_points = [
        G1Affine { x: decoded[0], y: decoded[1] },
        G1Affine { x: decoded[6], y: decoded[7] },
        G1Affine { x: decoded[8], y: decoded[9] },
        G1Affine { x: decoded[10], y: decoded[11] },
    ];
    for p in g1_points {
        assert(!p.is_infinity(), "Runtime Groth16 pairing G1 point must be finite");
    }
    let b = decode_g2(decoded, 2);
    let beta = decode_g2(decoded, 12);
    let gamma = decode_g2(decoded, 16);
    let delta = decode_g2(decoded, 20);
    let original_g2 = [b, beta, gamma, delta];
    for p in original_g2 {
        assert(!p.is_infinity(), "Runtime Groth16 G2 point must be finite");
        assert(is_on_curve_g2_affine(p), "Invalid runtime Groth16 G2 curve point");
    }
    // e(A,B) e(C,-delta) e(L,-gamma) e(-alpha,beta) = 1.
    let origins = [b, neg_g2_affine(delta), neg_g2_affine(gamma), beta];
    let mut transcript_coeffs = [[0; 3]; 852];
    for i in 0..24 {
        transcript_coeffs[i] = raw[i];
    }
    for i in 0..36 {
        transcript_coeffs[24 + i] = residue[i];
    }
    for i in 0..66 {
        for j in 0..12 {
            transcript_coeffs[60 + 12 * i + j] = accumulators[i][j];
        }
    }
    let rho_field = transcript_hash(
        [DOMAIN, 68, context[0], context[1], context[2]],
        transcript_coeffs,
    );
    assert(rho_field != 0);
    let rho = Fp::from(rho_field);
    let powers = powers(Fp::from(transcript_hash([DOMAIN + 1, rho_field], quotient)));
    let weights = tower_weights(powers);
    let lw = [
        line_weights(decoded[0], decoded[1], powers),
        line_weights(decoded[6], decoded[7], powers),
        line_weights(decoded[8], decoded[9], powers),
        line_weights(decoded[10], decoded[11].neg(), powers),
    ];
    let c = dot(twelve(res, 0), weights);
    let ci = dot(twelve(res, 12), weights);
    let evals = accs.map(|a| dot(a, weights));
    let mut products = [Fp::from(0); 68];
    let mut outputs = products;
    products[0] = c * ci;
    outputs[0] = Fp::from(1);
    let (points, intermediate, prefix) = initialize(origins, lw, c, ci, evals[0]);
    products[1] = intermediate;
    outputs[1] = evals[0];
    products[2] = prefix;
    outputs[2] = evals[1];

    // Ordinary unconditional helper calls bound compiler expansion; they do
    // not introduce private calls, new transcripts, or intermediate acceptance.
    let (points, p0) = rounds::<0, 8>(origins, points, lw, evals, c, ci);
    let (points, p1) = rounds::<8, 8>(origins, points, lw, evals, c, ci);
    let (points, p2) = rounds::<16, 8>(origins, points, lw, evals, c, ci);
    let (points, p3) = rounds::<24, 8>(origins, points, lw, evals, c, ci);
    let (points, p4) = rounds::<32, 8>(origins, points, lw, evals, c, ci);
    let (points, p5) = rounds::<40, 8>(origins, points, lw, evals, c, ci);
    let (points, p6) = rounds::<48, 8>(origins, points, lw, evals, c, ci);
    let (points, p7) = rounds::<56, 7>(origins, points, lw, evals, c, ci);
    for i in 0..8 {
        products[3 + i] = p0[i];
        products[11 + i] = p1[i];
        products[19 + i] = p2[i];
        products[27 + i] = p3[i];
        products[35 + i] = p4[i];
        products[43 + i] = p5[i];
        products[51 + i] = p6[i];
    }
    for i in 0..7 {
        products[59 + i] = p7[i];
    }
    for i in 0..63 {
        outputs[3 + i] = evals[i + 2];
    }
    let (tail_lines, terminal) = finish(origins, points, lw, evals[64], evals[65], res, weights);
    products[66] = tail_lines;
    outputs[66] = evals[65];
    products[67] = terminal;
    outputs[67] = Fp::from(1);
    assert_global_relations_68(products, outputs, rho, q, powers, residuals);
}

fn decode_g2(raw: [Fp; 24], offset: u32) -> G2Affine {
    G2Affine { x: fp2(raw[offset], raw[offset + 1]), y: fp2(raw[offset + 2], raw[offset + 3]) }
}

#[no_predicates]
fn initialize(
    origins: [G2Affine; 4],
    lw: [[Fp; 6]; 4],
    c: Fp,
    ci: Fp,
    h: Fp,
) -> ([G2Affine; 4], Fp, Fp) {
    let mut points = origins;
    let mut product = ci * ci;
    let mut corrections = [Fp::from(1); 4];
    for k in 0..4 {
        let (twice, d) = double_step(origins[k]);
        product = product * line_value(d, lw[k]);
        let (_, l) = line_compute(twice, neg_g2_affine(origins[k]));
        let (triple, a) = add_step(twice, origins[k]);
        points[k] = triple;
        corrections[k] = line_value(l, lw[k]) * line_value(a, lw[k]);
    }
    let intermediate = product;
    product = h * h;
    for k in 0..4 {
        product = product * corrections[k];
    }
    (points, intermediate, product * c)
}

#[no_predicates]
fn rounds<let START: u32, let COUNT: u32>(
    origins: [G2Affine; 4],
    points: [G2Affine; 4],
    lw: [[Fp; 6]; 4],
    evals: [Fp; 66],
    c: Fp,
    ci: Fp,
) -> ([G2Affine; 4], [Fp; COUNT]) {
    let mut points = points;
    let mut products = [Fp::from(0); COUNT];
    for i in 0..COUNT {
        let index = START + i;
        let digit = fields::fp::miller_loop_digits()[62 - index];
        let mut product = evals[index + 1] * evals[index + 1];
        for k in 0..4 {
            let (next, d) = double_step(points[k]);
            points[k] = next;
            product = product * line_value(d, lw[k]);
            if digit != 0 {
                let (next, a) = add_step(
                    points[k],
                    if digit == 1 {
                        origins[k]
                    } else {
                        neg_g2_affine(origins[k])
                    },
                );
                points[k] = next;
                product = product * line_value(a, lw[k]);
            }
        }
        if digit != 0 {
            product = product * (if digit == 1 { ci } else { c });
        }
        products[i] = product;
    }
    (points, products)
}

#[no_predicates]
fn finish(
    origins: [G2Affine; 4],
    points: [G2Affine; 4],
    lw: [[Fp; 6]; 4],
    last: Fp,
    tail: Fp,
    res: [Fp; 36],
    weights: [Fp; 12],
) -> (Fp, Fp) {
    let mut product = last;
    for k in 0..4 {
        let (point, a) = add_step(points[k], frobenius_g2(origins[k]));
        let q2 = frobenius_square_g2(origins[k]); // This helper is -psi^2.
        // This exact endpoint equality proves subgroup membership, for each
        // runtime G2 point, after its constrained full-twist Miller schedule.
        let l = line_with_endpoint(point, q2, frobenius_g2(q2));
        product = product * line_value(a, lw[k]) * line_value(l, lw[k]);
    }
    let tail_lines = product;
    product = tail;
    let c = fp12(twelve(res, 0));
    let ci = fp12(twelve(res, 12));
    product = product * dot(twelve(res, 24), weights);
    let (first, second, third) = residue_frobenius_evaluations(c, ci, weights);
    product = product * first;
    product = product * second;
    product = product * third;
    (tail_lines, product)
}

// These local representatives retain120/120/14 bounds. Accumulators and Q
// are injectively committed before challenges; residuals are bound by exact
// equations. No internal representative crosses a verification boundary.
fn bounded(limbs: [u128; 3]) -> Fp {
    Fp::from_limbs(limbs)
}
