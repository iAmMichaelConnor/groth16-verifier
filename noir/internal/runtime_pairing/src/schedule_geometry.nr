// PRIVATE fixed BN254 Miller schedule implementation.
// Precondition: the caller establishes finite B on the twist
// y^2 = x^3 + 3/(9+u) over Fq2 and threads the exact preceding point. B is not
// assumed to be in G2; the terminal endpoint relation proves that.
// Under this precondition no denominator is zero: E'(Fq2) is cyclic (squarefree
// cofactor), and for every doubling, addition and line of the schedule the
// scalar gcds with r*h are 1. noir/groth16/tests/check_schedule_denominators.py recomputes
// these gcds from fields/src/fp.nr's digits; the derivation is in its docstring.
// Re-run it whenever the digits or the schedule change.
// All exact slope/intercept/endpoint equations and BigNum bounds remain.
// This module MUST NOT be exposed as generic unchecked affine arithmetic.
use bignum::bignum::evaluate_quadratic_expression;
use fields::fp::Fp;
use fields::fp2::Fp2;
use g2::affine;
use g2::g2::{G2Affine, LineEvaluation};
use pairing_checks::polynomial::fp2;

unconstrained fn affine_hint(p: G2Affine, q: G2Affine, is_double: bool) -> affine::AffineStep {
    let s = if is_double {
        p.x.square().mul_by_element(Fp::from(3)).mul(p.y.double().inverse())
    } else {
        q.y.sub(p.y).mul(q.x.sub(p.x).inverse())
    };
    let x = s.square().sub(p.x).sub(q.x);
    let y = s.mul(p.x.sub(x)).sub(p.y);
    affine::AffineStep { slope: s, result: G2Affine { x, y } }
}

unconstrained fn intercept_hint(p: G2Affine, s: Fp2) -> Fp2 {
    s.mul(p.x).sub(p.y)
}

pub fn normalized_line(p: G2Affine, s: Fp2) -> LineEvaluation {
    // Safety: both intercept coefficients occur in these exact bounded equations.
    let t = unsafe { intercept_hint(p, s) };
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[p.x.c0], [p.x.c1]],
        [[false]; 2],
        [p.y.c0, t.c0],
        [true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false]; 2],
        [[p.x.c1], [p.x.c0]],
        [[false]; 2],
        [p.y.c1, t.c1],
        [true, true],
    );
    LineEvaluation { r0: fp2(Fp::from(1), Fp::from(0)), r1: s.neg(), r2: t }
}

pub fn double_step(p: G2Affine) -> (G2Affine, LineEvaluation) {
    // Safety: exact affine equations are checked; nonzero denominator follows the audited fixed schedule.
    let w = unsafe { affine_hint(p, p, true) };
    let line = normalized_line(p, w.slope);
    let next = double_given_checked_intercept(p, w, line.r2);
    (next, line)
}

pub fn add_step(p: G2Affine, q: G2Affine) -> (G2Affine, LineEvaluation) {
    // Safety: exact affine equations are checked; nonzero denominator follows the audited fixed schedule.
    let w = unsafe { affine_hint(p, q, false) };
    let line = normalized_line(p, w.slope);
    let next = add_given_checked_intercept(p, q, w, line.r2);
    (next, line)
}

unconstrained fn add_slope_hint(p: G2Affine, q: G2Affine) -> Fp2 {
    q.y.sub(p.y).mul(q.x.sub(p.x).inverse())
}

pub fn add_slope(p: G2Affine, q: G2Affine) -> Fp2 {
    // Safety: every returned coefficient occurs in the exact division relation.
    let s = unsafe { add_slope_hint(p, q) };
    evaluate_quadratic_expression(
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [true], [false]],
        [[q.x.c0], [p.x.c0], [q.x.c1], [p.x.c1]],
        [[false]; 4],
        [q.y.c0, p.y.c0],
        [true, false],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [false], [true]],
        [[q.x.c1], [p.x.c1], [q.x.c0], [p.x.c0]],
        [[false]; 4],
        [q.y.c1, p.y.c1],
        [true, false],
    );
    s
}

pub fn line_compute(p: G2Affine, q: G2Affine) -> (G2Affine, LineEvaluation) {
    (p, normalized_line(p, add_slope(p, q)))
}

pub fn line_with_endpoint(p: G2Affine, q: G2Affine, r: G2Affine) -> LineEvaluation {
    let s = add_slope(p, q);
    let line = normalized_line(p, s);
    let intercept = line.r2;
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[s.c0], [s.c1]],
        [[false]; 2],
        [p.x.c0, q.x.c0, r.x.c0],
        [true; 3],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0]],
        [[false]; 2],
        [[s.c1], [s.c1]],
        [[false]; 2],
        [p.x.c1, q.x.c1, r.x.c1],
        [true; 3],
    );
    // y_R = intercept - slope*x_R; share the already-constrained intercept.
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[r.x.c0], [r.x.c1]],
        [[false]; 2],
        [r.y.c0, intercept.c0],
        [false, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false]; 2],
        [[r.x.c1], [r.x.c0]],
        [[false]; 2],
        [r.y.c1, intercept.c1],
        [false, true],
    );
    line
}

// Private helper: caller must have constrained t=s*x_P-y_P with normalized_line.
fn double_given_checked_intercept(p: G2Affine, w: affine::AffineStep, t: Fp2) -> G2Affine {
    let s = w.slope;
    let r = w.result;
    evaluate_quadratic_expression(
        [
            [s.c0], [s.c0], [s.c1], [s.c1], [p.x.c0], [p.x.c0], [p.x.c0], [p.x.c1], [p.x.c1],
            [p.x.c1],
        ],
        [[false], [false], [true], [true], [true], [true], [true], [false], [false], [false]],
        [
            [p.y.c0], [p.y.c0], [p.y.c1], [p.y.c1], [p.x.c0], [p.x.c0], [p.x.c0], [p.x.c1],
            [p.x.c1], [p.x.c1],
        ],
        [[false]; 10],
        [Fp::from(0)],
        [false],
    );
    evaluate_quadratic_expression(
        [
            [s.c0], [s.c0], [s.c1], [s.c1], [p.x.c0], [p.x.c0], [p.x.c0], [p.x.c0], [p.x.c0],
            [p.x.c0],
        ],
        [[false], [false], [false], [false], [true], [true], [true], [true], [true], [true]],
        [
            [p.y.c1], [p.y.c1], [p.y.c0], [p.y.c0], [p.x.c1], [p.x.c1], [p.x.c1], [p.x.c1],
            [p.x.c1], [p.x.c1],
        ],
        [[false]; 10],
        [Fp::from(0)],
        [false],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[s.c0], [s.c1]],
        [[false]; 2],
        [p.x.c0, p.x.c0, r.x.c0],
        [true, true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0]],
        [[false], [false]],
        [[s.c1], [s.c1]],
        [[false]; 2],
        [p.x.c1, p.x.c1, r.x.c1],
        [true, true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[r.x.c0], [r.x.c1]],
        [[false]; 2],
        [r.y.c0, t.c0],
        [false, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false]; 2],
        [[r.x.c1], [r.x.c0]],
        [[false]; 2],
        [r.y.c1, t.c1],
        [false, true],
    );
    r
}

// Private helper: caller must have constrained t=s*x_P-y_P with normalized_line.
fn add_given_checked_intercept(
    p: G2Affine,
    q: G2Affine,
    w: affine::AffineStep,
    t: Fp2,
) -> G2Affine {
    let s = w.slope;
    let r = w.result;
    evaluate_quadratic_expression(
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [true], [false]],
        [[q.x.c0], [p.x.c0], [q.x.c1], [p.x.c1]],
        [[false]; 4],
        [q.y.c0, p.y.c0],
        [true, false],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [false], [true]],
        [[q.x.c1], [p.x.c1], [q.x.c0], [p.x.c0]],
        [[false]; 4],
        [q.y.c1, p.y.c1],
        [true, false],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[s.c0], [s.c1]],
        [[false]; 2],
        [p.x.c0, q.x.c0, r.x.c0],
        [true, true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0]],
        [[false], [false]],
        [[s.c1], [s.c1]],
        [[false]; 2],
        [p.x.c1, q.x.c1, r.x.c1],
        [true, true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false], [true]],
        [[r.x.c0], [r.x.c1]],
        [[false]; 2],
        [r.y.c0, t.c0],
        [false, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c1]],
        [[false]; 2],
        [[r.x.c1], [r.x.c0]],
        [[false]; 2],
        [r.y.c1, t.c1],
        [false, true],
    );
    r
}
