use crate::g2::{add_g2_jac, double_g2_jac, g2_affine_to_jacobian, G2Affine, G2Jac, psi_g2};
use bignum::bignum::evaluate_quadratic_expression;
use fields::BigNum;
use fields::fp::{fp_three, fp_zero};
use fields::fp2::Fp2;

fn equal(a: Fp2, b: Fp2) -> bool {
    (a.c0 == b.c0) & (a.c1 == b.c1)
}
fn nonzero(a: Fp2) {
    a.c0.validate_in_range();
    a.c1.validate_in_range();
    assert(!(a.c0.is_zero() & a.c1.is_zero()), "Exceptional affine denominator");
}

unconstrained fn double_hint(p: G2Affine) -> (Fp2, G2Affine) {
    let slope = p.x.square().mul_by_element(fp_three()).mul(p.y.double().inverse());
    let x = slope.square().sub(p.x.double());
    let y = slope.mul(p.x.sub(x)).sub(p.y);
    (slope, G2Affine { x, y })
}
unconstrained fn add_hint(p: G2Affine, q: G2Affine) -> (Fp2, G2Affine) {
    let slope = q.y.sub(p.y).mul(q.x.sub(p.x).inverse());
    let x = slope.square().sub(p.x).sub(q.x);
    let y = slope.mul(p.x.sub(x)).sub(p.y);
    (slope, G2Affine { x, y })
}

/// Constrained affine doubling. All six hint coefficients occur in exact equations.
pub fn double(p: G2Affine) -> G2Affine {
    // Safety: exact equations in double_with_witness constrain the hint.
    let (s, r) = unsafe { double_hint(p) };
    double_with_witness(p, AffineStep { slope: s, result: r })
}
pub fn double_with_witness(p: G2Affine, w: AffineStep) -> G2Affine {
    nonzero(p.y);
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
        [fp_zero()],
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
        [fp_zero()],
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
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [true], [false]],
        [[p.x.c0], [r.x.c0], [p.x.c1], [r.x.c1]],
        [[false]; 4],
        [p.y.c0, r.y.c0],
        [true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [false], [true]],
        [[p.x.c1], [r.x.c1], [p.x.c0], [r.x.c0]],
        [[false]; 4],
        [p.y.c1, r.y.c1],
        [true, true],
    );
    r
}

/// Incomplete addition with explicit rejection of every zero denominator.
/// Safe for an on-curve fixed scalar chain; never use without that precondition.
pub fn add(p: G2Affine, q: G2Affine) -> G2Affine {
    // Safety: exact equations in add_with_witness constrain the hint.
    let (s, r) = unsafe { add_hint(p, q) };
    add_with_witness(p, q, AffineStep { slope: s, result: r })
}
pub fn add_with_witness(p: G2Affine, q: G2Affine, w: AffineStep) -> G2Affine {
    nonzero(q.x.sub(p.x));
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
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [true], [false]],
        [[p.x.c0], [r.x.c0], [p.x.c1], [r.x.c1]],
        [[false]; 4],
        [p.y.c0, r.y.c0],
        [true, true],
    );
    evaluate_quadratic_expression(
        [[s.c0], [s.c0], [s.c1], [s.c1]],
        [[false], [true], [false], [true]],
        [[p.x.c1], [r.x.c1], [p.x.c0], [r.x.c0]],
        [[false]; 4],
        [p.y.c1, r.y.c1],
        [true, true],
    );
    r
}

fn double_n<let N: u32>(p: G2Affine) -> G2Affine {
    let mut r = p;
    for _ in 0..N {
        r = double(r);
    }
    r
}
fn double_add(p: G2Affine, q: G2Affine) -> G2Affine {
    add(double(p), q)
}

/// gnark fixed-seed chain, checked symbolically by generate.py.
pub fn seed_mul(q: G2Affine) -> G2Affine {
    let mut z = double(q);
    let mut t0 = add(q, z);
    let mut t2 = add(q, t0);
    let mut t1 = add(z, t2);
    z = double_add(t1, t0);
    t0 = add(t0, z);
    t2 = add(t2, t0);
    t1 = add(t1, t2);
    t0 = add(t0, t1);
    t1 = add(t1, t0);
    t0 = add(t0, t1);
    t2 = add(t2, t0);
    t1 = double_add(t2, t1);
    t2 = add(t2, t1);
    z = add(z, t2);
    t2 = add(t2, z);
    z = double_add(t2, z);
    t0 = add(t0, z);
    t1 = add(t1, t0);
    let mut t3 = double(t1);
    t3 = double_add(t3, t1);
    t2 = add(t2, t3);
    t1 = add(t1, t2);
    t2 = add(t2, t1);
    t2 = double_n::<16>(t2);
    t1 = double_add(t2, t1);
    t1 = double_n::<13>(t1);
    t0 = double_add(t1, t0);
    t0 = double_n::<15>(t0);
    z = double_add(t0, z);
    z
}

/// Same short-vector subgroup criterion as the shared implementation.
/// Caller must first assert on-curve membership and non-infinity.
pub fn subgroup(p: G2Affine) -> bool {
    let xq = g2_affine_to_jacobian(seed_mul(p));
    let psi1 = psi_g2(xq);
    let psi2 = psi_g2(psi1);
    let psi3 = psi_g2(psi2);
    let twice_psi3 = double_g2_jac(psi3);
    let neg_psi2 = G2Jac { x: psi2.x, y: psi2.y.neg(), z: psi2.z };
    let neg_psi1 = G2Jac { x: psi1.x, y: psi1.y.neg(), z: psi1.z };
    let neg_xq = G2Jac { x: xq.x, y: xq.y.neg(), z: xq.z };
    let check = add_g2_jac(
        add_g2_jac(add_g2_jac(twice_psi3, neg_psi2), neg_psi1),
        neg_xq,
    );
    let zz = check.z.square();
    !check.is_infinity() & equal(check.x, p.x.mul(zz)) & equal(check.y, p.y.mul(zz.mul(check.z)))
}

pub struct AffineStep {
    pub slope: Fp2,
    pub result: G2Affine,
}
pub fn seed_mul_supplied(q: G2Affine, w: [AffineStep; 78]) -> G2Affine {
    let mut z = double_with_witness(q, w[0]);
    let mut t0 = add_with_witness(q, z, w[1]);
    let mut t2 = add_with_witness(q, t0, w[2]);
    let mut t1 = add_with_witness(z, t2, w[3]);
    z = add_with_witness(double_with_witness(t1, w[4]), t0, w[5]);
    t0 = add_with_witness(t0, z, w[6]);
    t2 = add_with_witness(t2, t0, w[7]);
    t1 = add_with_witness(t1, t2, w[8]);
    t0 = add_with_witness(t0, t1, w[9]);
    t1 = add_with_witness(t1, t0, w[10]);
    t0 = add_with_witness(t0, t1, w[11]);
    t2 = add_with_witness(t2, t0, w[12]);
    t1 = add_with_witness(double_with_witness(t2, w[13]), t1, w[14]);
    t2 = add_with_witness(t2, t1, w[15]);
    z = add_with_witness(z, t2, w[16]);
    t2 = add_with_witness(t2, z, w[17]);
    z = add_with_witness(double_with_witness(t2, w[18]), z, w[19]);
    t0 = add_with_witness(t0, z, w[20]);
    t1 = add_with_witness(t1, t0, w[21]);
    let mut t3 = double_with_witness(t1, w[22]);
    t3 = add_with_witness(double_with_witness(t3, w[23]), t1, w[24]);
    t2 = add_with_witness(t2, t3, w[25]);
    t1 = add_with_witness(t1, t2, w[26]);
    t2 = add_with_witness(t2, t1, w[27]);
    t2 = t2;
    for i in 0..16 {
        t2 = double_with_witness(t2, w[28 + i]);
    }
    t1 = add_with_witness(double_with_witness(t2, w[44]), t1, w[45]);
    t1 = t1;
    for i in 0..13 {
        t1 = double_with_witness(t1, w[46 + i]);
    }
    t0 = add_with_witness(double_with_witness(t1, w[59]), t0, w[60]);
    t0 = t0;
    for i in 0..15 {
        t0 = double_with_witness(t0, w[61 + i]);
    }
    z = add_with_witness(double_with_witness(t0, w[76]), z, w[77]);
    z
}
pub fn subgroup_supplied(p: G2Affine, w: [AffineStep; 78]) -> bool {
    let xq = g2_affine_to_jacobian(seed_mul_supplied(p, w));
    let psi1 = psi_g2(xq);
    let psi2 = psi_g2(psi1);
    let psi3 = psi_g2(psi2);
    let twice_psi3 = double_g2_jac(psi3);
    let neg_psi2 = G2Jac { x: psi2.x, y: psi2.y.neg(), z: psi2.z };
    let neg_psi1 = G2Jac { x: psi1.x, y: psi1.y.neg(), z: psi1.z };
    let neg_xq = G2Jac { x: xq.x, y: xq.y.neg(), z: xq.z };
    let check = add_g2_jac(
        add_g2_jac(add_g2_jac(twice_psi3, neg_psi2), neg_psi1),
        neg_xq,
    );
    let zz = check.z.square();
    !check.is_infinity() & equal(check.x, p.x.mul(zz)) & equal(check.y, p.y.mul(zz.mul(check.z)))
}
