use crate::fp::{fp_three, seed_x0};
use crate::fp2::{b_twist, endo_u, endo_v, Fp2, fp2_one, fp2_zero};

/// G2 affine point over Fp2.
pub struct G2Affine {
    pub x: Fp2,
    pub y: Fp2,
}

/// G2 Jacobian point (X:Y:Z) representing (X/Z^2, Y/Z^3).
pub struct G2Jac {
    pub x: Fp2,
    pub y: Fp2,
    pub z: Fp2,
}

/// G2 projective point used for Miller loop steps.
pub struct G2Proj {
    pub x: Fp2,
    pub y: Fp2,
    pub z: Fp2,
}

/// Line function l_{R,P}(Q) coefficients for Miller loop evaluation.
pub struct LineEvaluation {
    pub r0: Fp2,
    pub r1: Fp2,
    pub r2: Fp2,
}

/// Raw line schedule for a single G2 point (un-evaluated coefficients).
pub struct LineScheduleRaw {
    pub initial_double: LineEvaluation,
    pub pre_loop_line: LineEvaluation,
    pub pre_loop_add: LineEvaluation,
    pub loop_doubles: [LineEvaluation; 63],
    pub loop_adds_pos: [LineEvaluation; 63],
    pub loop_adds_neg: [LineEvaluation; 63],
    pub final_add: LineEvaluation,
    pub final_line: LineEvaluation,
}

/// Affine point at infinity (0, 0).
pub fn g2_affine_infinity() -> G2Affine {
    G2Affine { x: fp2_zero(), y: fp2_zero() }
}

/// Jacobian point at infinity (1, 1, 0).
pub fn g2_jacobian_infinity() -> G2Jac {
    G2Jac { x: fp2_one(), y: fp2_one(), z: fp2_zero() }
}

impl G2Affine {
    pub fn is_infinity(self) -> bool {
        let x_zero = fp2_is_zero(self.x);
        let y_zero = fp2_is_zero(self.y);
        x_zero & y_zero
    }
}

impl G2Jac {
    pub fn is_infinity(self) -> bool {
        fp2_is_zero(self.z)
    }
}

/// Check y^2 = x^3 + b' for affine points, treating infinity as valid.
pub fn is_on_curve_g2_affine(p: G2Affine) -> bool {
    let left = p.y.square();
    let right = p.x.square().mul(p.x).add(b_twist());
    if p.is_infinity() {
        true
    } else {
        fp2_eq(left, right)
    }
}

/// Affine negation: (x, y) -> (x, -y).
pub fn neg_g2_affine(p: G2Affine) -> G2Affine {
    G2Affine { x: p.x, y: p.y.neg() }
}

/// Convert Jacobian to affine with a single inversion.
pub fn jacobian_to_affine_g2(p: G2Jac) -> G2Affine {
    if p.is_infinity() {
        g2_affine_infinity()
    } else {
        let a = p.z.inverse();
        let b = a.square();
        let x = p.x.mul(b);
        let y = p.y.mul(b).mul(a);
        G2Affine { x, y }
    }
}

/// Convert affine to Jacobian (Z = 1), preserving infinity.
pub fn g2_affine_to_jacobian(p: G2Affine) -> G2Jac {
    if p.is_infinity() {
        g2_jacobian_infinity()
    } else {
        G2Jac { x: p.x, y: p.y, z: fp2_one() }
    }
}

/// Scalar multiplication by a 128-bit constant using double-and-add.
pub fn scalar_mul_g2_by_u128(p: G2Jac, scalar: u128) -> G2Jac {
    let mut acc = g2_jacobian_infinity();
    let mut base = p;
    let mut k = scalar;
    for _ in 0..128 {
        let bit: bool = (k & 1) == 1;
        if bit {
            acc = add_g2_jac(acc, base);
        }
        base = double_g2_jac(base);
        k = k >> 1;
    }
    acc
}

/// G2 membership: P is finite, on the twist y^2 = x^3 + 3/(9+u), and
/// psi(P) == [6x^2]P. The on-twist check is required: the psi test alone also
/// accepts r-torsion points of other curves y^2 = x^3 + k*b'.
pub fn is_in_correct_subgroup_g2(p: G2Affine) -> bool {
    if p.is_infinity() {
        false
    } else {
        let p_jac = g2_affine_to_jacobian(p);
        let psi = psi_g2(p_jac);
        let x = seed_x0();
        let x2 = x * x;
        let k = x2 * 6;
        let x_p = scalar_mul_g2_by_u128(p_jac, k);
        let psi_aff = jacobian_to_affine_g2(psi);
        let x_aff = jacobian_to_affine_g2(x_p);
        is_on_curve_g2_affine(p) & fp2_eq(psi_aff.x, x_aff.x) & fp2_eq(psi_aff.y, x_aff.y)
    }
}

/// Jacobian addition with no inversions (complete with special cases).
pub fn add_g2_jac(p: G2Jac, q: G2Jac) -> G2Jac {
    if p.is_infinity() {
        q
    } else if q.is_infinity() {
        p
    } else {
        let z1z1 = q.z.square();
        let z2z2 = p.z.square();
        let u1 = q.x.mul(z2z2);
        let u2 = p.x.mul(z1z1);
        let s1 = q.y.mul(p.z).mul(z2z2);
        let s2 = p.y.mul(q.z).mul(z1z1);
        let same_u = fp2_eq(u1, u2);
        let same_s = fp2_eq(s1, s2);

        if same_u & same_s {
            double_g2_jac(p)
        } else {
            let h = u2.sub(u1);
            let i = h.double().square();
            let j = h.mul(i);
            let r = s2.sub(s1).double();
            let v = u1.mul(i);

            let x3 = r.square().sub(j).sub(v.double());
            let y3 = r.mul(v.sub(x3)).sub(s1.double().mul(j));
            let z3 = p.z.add(q.z).square().sub(z1z1).sub(z2z2).mul(h);
            G2Jac { x: x3, y: y3, z: z3 }
        }
    }
}

/// Jacobian point doubling (used in scalar multiplication).
pub fn double_g2_jac(p: G2Jac) -> G2Jac {
    let a = p.x.square();
    let b = p.y.square();
    let c = b.square();
    let d = (p.x.add(b)).square().sub(a).sub(c).double();
    let e = a.double().add(a);
    let f = e.square();
    let t = d.double();

    let z3 = p.y.mul(p.z).double();
    let x3 = f.sub(t);
    let y3 = e.mul(d.sub(x3)).sub(c.double().double().double());
    G2Jac { x: x3, y: y3, z: z3 }
}

/// Convert affine to projective (Z = 1) for Miller loop steps.
pub fn projective_from_affine_g2(a: G2Affine) -> G2Proj {
    if a.is_infinity() {
        G2Proj { x: fp2_one(), y: fp2_one(), z: fp2_zero() }
    } else {
        G2Proj { x: a.x, y: a.y, z: fp2_one() }
    }
}

/// Frobenius map on the twist: Q -> Q^p with precomputed coefficients.
pub fn frobenius_g2(q: G2Affine) -> G2Affine {
    let x = q.x.conjugate().mul_by_non_residue_1_power_2();
    let y = q.y.conjugate().mul_by_non_residue_1_power_3();
    G2Affine { x, y }
}

/// Returns -psi^2(Q): the Frobenius^2 twist map with y negated, the operand of
/// the last optimal-Ate line. Callers that need psi^2(Q) itself must negate y.
pub fn frobenius_square_g2(q: G2Affine) -> G2Affine {
    let x = q.x.mul_by_non_residue_2_power_2();
    let y = q.y.mul_by_non_residue_2_power_3().neg();
    G2Affine { x, y }
}

/// Endomorphism psi: conjugation + constants (GLV-style on BN curves).
pub fn psi_g2(p: G2Jac) -> G2Jac {
    let x = p.x.conjugate().mul(endo_u());
    let y = p.y.conjugate().mul(endo_v());
    let z = p.z.conjugate();
    G2Jac { x, y, z }
}

impl G2Proj {
    /// Doubling step that also returns the tangent line evaluation.
    pub fn double_step(self) -> (G2Proj, LineEvaluation) {
        let a = self.x.mul(self.y).halve();
        let b = self.y.square();
        let c = self.z.square();
        let d = c.mul_by_element(fp_three());
        let e = d.mul_by_b_twist_coeff();
        let f = e.mul_by_element(fp_three());
        let g = b.add(f).halve();
        let h = self.y.add(self.z).square().sub(b).sub(c);
        let i = e.sub(b);
        let j = self.x.square();
        let ee = e.square();
        let k = ee.mul_by_element(fp_three());

        let x = b.sub(f).mul(a);
        let y = g.square().sub(k);
        let z = b.mul(h);

        let line = LineEvaluation { r0: h.neg(), r1: j.mul_by_element(fp_three()), r2: i };
        (G2Proj { x, y, z }, line)
    }

    /// Mixed addition step (projective + affine) with line evaluation.
    pub fn add_mixed_step(self, a: G2Affine) -> (G2Proj, LineEvaluation) {
        let y2z1 = a.y.mul(self.z);
        let o = self.y.sub(y2z1);
        let x2z1 = a.x.mul(self.z);
        let l = self.x.sub(x2z1);
        let c = o.square();
        let d = l.square();
        let e = l.mul(d);
        let f = self.z.mul(c);
        let g = self.x.mul(d);
        let t0 = g.double();
        let h = e.add(f).sub(t0);
        let t1 = self.y.mul(e);

        let x = l.mul(h);
        let y = g.sub(h).mul(o).sub(t1);
        let z = e.mul(self.z);

        let t2 = l.mul(a.y);
        let j = a.x.mul(o).sub(t2);
        let line = LineEvaluation { r0: l, r1: o.neg(), r2: j };

        (G2Proj { x, y, z }, line)
    }

    /// Compute the line evaluation for adding affine a to self.
    pub fn line_compute(self, a: G2Affine) -> (G2Proj, LineEvaluation) {
        let y2z1 = a.y.mul(self.z);
        let o = self.y.sub(y2z1);
        let x2z1 = a.x.mul(self.z);
        let l = self.x.sub(x2z1);
        let t2 = l.mul(a.y);
        let j = a.x.mul(o).sub(t2);

        let line = LineEvaluation { r0: l, r1: o.neg(), r2: j };
        (self, line)
    }
}

fn fp2_is_zero(a: Fp2) -> bool {
    let z = fp2_zero();
    let c0_zero = a.c0 == z.c0;
    let c1_zero = a.c1 == z.c1;
    c0_zero & c1_zero
}

fn fp2_eq(a: Fp2, b: Fp2) -> bool {
    let c0_eq = a.c0 == b.c0;
    let c1_eq = a.c1 == b.c1;
    c0_eq & c1_eq
}

/// Short-vector BN254 subgroup test using one scalar multiplication by the
/// 63-bit curve seed. See ePrint 2022/348, section 3.1.2 (Example 1), and gnark's
/// sw_bn254.computeG2ShortVector. Like is_in_correct_subgroup_g2, it also
/// requires P finite and on the twist.
pub fn is_in_correct_subgroup_g2_fast(p: G2Affine) -> bool {
    if p.is_infinity() {
        false
    } else {
        let xq = scalar_mul_g2_by_u128(g2_affine_to_jacobian(p), seed_x0());
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
        let expected_x = p.x.mul(zz);
        let expected_y = p.y.mul(zz.mul(check.z));
        is_on_curve_g2_affine(p)
            & !check.is_infinity()
            & fp2_eq(check.x, expected_x)
            & fp2_eq(check.y, expected_y)
    }
}

// Vectors printed and checked by scripts/tests/g2_subgroup_vectors.py.
#[test]
fn subgroup_helpers_reject_off_twist_r_torsion_point() {
    // A finite point of order r on y^2 = x^3 + 2b', not on the twist.
    let p = G2Affine {
        x: Fp2 {
            c0: crate::fp::fp_from_limbs_checked([
                0xc233b2f7e0907e9de2b091ce49b2d1,
                0x4bcffba966550c37012970d120e71d,
                0x1e54,
            ]),
            c1: crate::fp::fp_from_limbs_checked([
                0x492d33a30dce3d17ac826250de49b8,
                0x620bb155b489dade2e39a5c588e2ed,
                0x149f,
            ]),
        },
        y: Fp2 {
            c0: crate::fp::fp_from_limbs_checked([
                0xa8f725e1694ef49a2a24fd56930635,
                0x833980cead751170a6416e71305ec3,
                0x24ed,
            ]),
            c1: crate::fp::fp_from_limbs_checked([
                0x37d077f705a02de4fc5e7c1b672724,
                0x28836117b97fb9bb2d6d023ae21492,
                0x1b78,
            ]),
        },
    };
    assert(!is_on_curve_g2_affine(p));
    assert(!is_in_correct_subgroup_g2(p));
    assert(!is_in_correct_subgroup_g2_fast(p));
}

#[test]
fn subgroup_helpers_accept_g2_generator() {
    let p = G2Affine {
        x: Fp2 {
            c0: crate::fp::fp_from_limbs_checked([
                0x4322d4f75edadd46debd5cd992f6ed,
                0xdeef121f1e76426a00665e5c447967,
                0x1800,
            ]),
            c1: crate::fp::fp_from_limbs_checked([
                0xaa493335a9e71297e485b7aef312c2,
                0x9393920d483a7260bfb731fb5d25f1,
                0x198e,
            ]),
        },
        y: Fp2 {
            c0: crate::fp::fp_from_limbs_checked([
                0xd1e7690c43d37b4ce6cc0166fa7daa,
                0x5ea5db8c6deb4aab71808dcb408fe3,
                0x12c8,
            ]),
            c1: crate::fp::fp_from_limbs_checked([
                0x4b313370b38ef355acdadcd122975b,
                0x89d0585ff075ec9e99ad690c3395bc,
                0x906,
            ]),
        },
    };
    assert(is_on_curve_g2_affine(p));
    assert(is_in_correct_subgroup_g2(p));
    assert(is_in_correct_subgroup_g2_fast(p));
}
