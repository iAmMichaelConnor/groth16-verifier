use crate::fp::fp_nine;
use crate::fp2::{Fp2, fp2_one, fp2_zero};
use crate::fp6::{Fp6, fp6_one, fp6_zero};
use bignum::bignum::evaluate_quadratic_expression;

// Fp12 = Fp6[w] / (w^2 - v)
/// Quadratic extension field element c0 + c1 * w.
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

pub fn fp12_zero() -> Fp12 {
    Fp12 { c0: fp6_zero(), c1: fp6_zero() }
}

pub fn fp12_one() -> Fp12 {
    Fp12 { c0: fp6_one(), c1: fp6_zero() }
}

impl Fp12 {
    /// Check whether the element equals 1 in Fp12.
    pub fn is_one(self) -> bool {
        let zero = fp2_zero();
        let one = fp2_one();
        let c0_b0 = (self.c0.b0.c0 == one.c0) & (self.c0.b0.c1 == one.c1);
        let c0_b1 = (self.c0.b1.c0 == zero.c0) & (self.c0.b1.c1 == zero.c1);
        let c0_b2 = (self.c0.b2.c0 == zero.c0) & (self.c0.b2.c1 == zero.c1);
        let c1_b0 = (self.c1.b0.c0 == zero.c0) & (self.c1.b0.c1 == zero.c1);
        let c1_b1 = (self.c1.b1.c0 == zero.c0) & (self.c1.b1.c1 == zero.c1);
        let c1_b2 = (self.c1.b2.c0 == zero.c0) & (self.c1.b2.c1 == zero.c1);
        c0_b0 & c0_b1 & c0_b2 & c1_b0 & c1_b1 & c1_b2
    }
    pub fn add(self, other: Fp12) -> Fp12 {
        Fp12 { c0: self.c0.add(other.c0), c1: self.c1.add(other.c1) }
    }

    pub fn sub(self, other: Fp12) -> Fp12 {
        Fp12 { c0: self.c0.sub(other.c0), c1: self.c1.sub(other.c1) }
    }

    pub fn neg(self) -> Fp12 {
        Fp12 { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    /// Conjugation: c0 - c1 * w.
    pub fn conjugate(self) -> Fp12 {
        Fp12 { c0: self.c0, c1: self.c1.neg() }
    }

    /// Karatsuba multiplication in Fp12.
    pub fn mul(self, other: Fp12) -> Fp12 {
        let a = (self.c0.add(self.c1)).mul(other.c0.add(other.c1));
        let b = self.c0.mul(other.c0);
        let c = self.c1.mul(other.c1);

        let c1 = a.sub(b).sub(c);
        let c0 = c.mul_by_non_residue().add(b);
        Fp12 { c0, c1 }
    }

    /// Squaring optimized for Fp12.
    unconstrained fn __square(self) -> Fp12 {
        let a = self.c0;
        let b = self.c1;
        let ab = a.mul(b);
        let c0 = a.square().add(b.square().mul_by_non_residue());
        let c1 = ab.double();
        Fp12 { c0, c1 }
    }

    /// Inversion via c0^2 - v*c1^2.
    pub fn inverse(self) -> Fp12 {
        let t0 = self.c0.square();
        let t1 = self.c1.square();
        let tmp = t1.mul_by_non_residue();
        let t0 = t0.sub(tmp);
        let t1 = t0.inverse();

        Fp12 { c0: self.c0.mul(t1), c1: self.c1.mul(t1).neg() }
    }

    /// Cyclotomic squaring in the r-torsion subgroup (Karabina 2010).
    pub fn cyclotomic_square(self) -> Fp12 {
        let t0 = self.c1.b1.square();
        let t1 = self.c0.b0.square();
        let t6 = (self.c1.b1.add(self.c0.b0)).square().sub(t0).sub(t1);
        let t2 = self.c0.b2.square();
        let t3 = self.c1.b0.square();
        let t7 = (self.c0.b2.add(self.c1.b0)).square().sub(t2).sub(t3);
        let t4 = self.c1.b2.square();
        let t5 = self.c0.b1.square();
        let t8 = (self.c1.b2.add(self.c0.b1)).square().sub(t4).sub(t5).mul_by_non_residue();

        let t0 = t0.mul_by_non_residue().add(t1);
        let t2 = t2.mul_by_non_residue().add(t3);
        let t4 = t4.mul_by_non_residue().add(t5);

        let z0 = t0.sub(self.c0.b0).double().add(t0);
        let z1 = t2.sub(self.c0.b1).double().add(t2);
        let z2 = t4.sub(self.c0.b2).double().add(t4);

        let z3 = t8.add(self.c1.b0).double().add(t8);
        let z4 = t6.add(self.c1.b1).double().add(t6);
        let z5 = t7.add(self.c1.b2).double().add(t7);

        Fp12 { c0: Fp6 { b0: z0, b1: z1, b2: z2 }, c1: Fp6 { b0: z3, b1: z4, b2: z5 } }
    }

    /// Frobenius map: (c0, c1) -> (c0^p, c1^p) with precomputed coefficients.
    pub fn frobenius(self) -> Fp12 {
        let t0 = self.c0.b0.conjugate();
        let t1 = self.c0.b1.conjugate().mul_by_non_residue_1_power_2();
        let t2 = self.c0.b2.conjugate().mul_by_non_residue_1_power_4();
        let t3 = self.c1.b0.conjugate().mul_by_non_residue_1_power_1();
        let t4 = self.c1.b1.conjugate().mul_by_non_residue_1_power_3();
        let t5 = self.c1.b2.conjugate().mul_by_non_residue_1_power_5();

        Fp12 { c0: Fp6 { b0: t0, b1: t1, b2: t2 }, c1: Fp6 { b0: t3, b1: t4, b2: t5 } }
    }

    /// Frobenius^2 map using sparse coefficients.
    pub fn frobenius_square(self) -> Fp12 {
        let t0 = self.c0.b0;
        let t1 = self.c0.b1.mul_by_non_residue_2_power_2();
        let t2 = self.c0.b2.mul_by_non_residue_2_power_4();
        let t3 = self.c1.b0.mul_by_non_residue_2_power_1();
        let t4 = self.c1.b1.mul_by_non_residue_2_power_3();
        let t5 = self.c1.b2.mul_by_non_residue_2_power_5();

        Fp12 { c0: Fp6 { b0: t0, b1: t1, b2: t2 }, c1: Fp6 { b0: t3, b1: t4, b2: t5 } }
    }

    /// Frobenius^3 map using sparse coefficients.
    pub fn frobenius_cube(self) -> Fp12 {
        let t0 = self.c0.b0.conjugate();
        let t1 = self.c0.b1.conjugate().mul_by_non_residue_3_power_2();
        let t2 = self.c0.b2.conjugate().mul_by_non_residue_3_power_4();
        let t3 = self.c1.b0.conjugate().mul_by_non_residue_3_power_1();
        let t4 = self.c1.b1.conjugate().mul_by_non_residue_3_power_3();
        let t5 = self.c1.b2.conjugate().mul_by_non_residue_3_power_5();

        Fp12 { c0: Fp6 { b0: t0, b1: t1, b2: t2 }, c1: Fp6 { b0: t3, b1: t4, b2: t5 } }
    }

    /// Multiply by sparse line element with non-zero coeffs in slots 0,3,4.
    unconstrained fn __mul_by_034(self, c0: Fp2, c3: Fp2, c4: Fp2) -> Fp12 {
        let a = self.c0.mul_by_e2(c0);
        let b = self.c1.mul_by_01(c3, c4);
        let d0 = c0.add(c3);
        let d = self.c0.add(self.c1).mul_by_01(d0, c4);

        let c1 = d.sub(a).sub(b);
        let c0 = b.mul_by_non_residue().add(a);

        Fp12 { c0, c1 }
    }

    pub fn mul_by_034(self, c0: Fp2, c3: Fp2, c4: Fp2) -> Fp12 {
        // Safety: twelve exact coefficient equations below constrain the entire hint.
        let result = unsafe { self.__mul_by_034(c0, c3, c4) };
        let c3_scaled = c3.mul_by_element(fp_nine());
        let c4_scaled = c4.mul_by_element(fp_nine());
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [[false], [true], [false], [true], [true], [true], [false], [true], [true], [true]],
            [
                [c0.c0],
                [c0.c1],
                [c4_scaled.c0],
                [c4.c1],
                [c4.c0],
                [c4_scaled.c1],
                [c3_scaled.c0],
                [c3.c1],
                [c3.c0],
                [c3_scaled.c1],
            ],
            [[false]; 10],
            [result.c0.b0.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [true], [false], [false], [false],
                [true],
            ],
            [
                [c0.c1],
                [c0.c0],
                [c4.c0],
                [c4_scaled.c1],
                [c4_scaled.c0],
                [c4.c1],
                [c3.c0],
                [c3_scaled.c1],
                [c3_scaled.c0],
                [c3.c1],
            ],
            [[false]; 10],
            [result.c0.b0.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [[false], [true], [false], [true], [false], [true], [true], [true]],
            [[c0.c0], [c0.c1], [c3.c0], [c3.c1], [c4_scaled.c0], [c4.c1], [c4.c0], [c4_scaled.c1]],
            [[false]; 8],
            [result.c0.b1.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [[false], [false], [false], [false], [false], [false], [false], [true]],
            [[c0.c1], [c0.c0], [c3.c1], [c3.c0], [c4.c0], [c4_scaled.c1], [c4_scaled.c0], [c4.c1]],
            [[false]; 8],
            [result.c0.b1.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
            ],
            [[false], [true], [false], [true], [false], [true]],
            [[c0.c0], [c0.c1], [c4.c0], [c4.c1], [c3.c0], [c3.c1]],
            [[false]; 6],
            [result.c0.b2.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
            ],
            [[false], [false], [false], [false], [false], [false]],
            [[c0.c1], [c0.c0], [c4.c1], [c4.c0], [c3.c1], [c3.c0]],
            [[false]; 6],
            [result.c0.b2.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
            ],
            [[false], [true], [false], [true], [true], [true], [false], [true]],
            [[c3.c0], [c3.c1], [c4_scaled.c0], [c4.c1], [c4.c0], [c4_scaled.c1], [c0.c0], [c0.c1]],
            [[false]; 8],
            [result.c1.b0.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
            ],
            [[false], [false], [false], [false], [false], [true], [false], [false]],
            [[c3.c1], [c3.c0], [c4.c0], [c4_scaled.c1], [c4_scaled.c0], [c4.c1], [c0.c1], [c0.c0]],
            [[false]; 8],
            [result.c1.b0.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
            ],
            [[false], [true], [false], [true], [false], [true]],
            [[c4.c0], [c4.c1], [c3.c0], [c3.c1], [c0.c0], [c0.c1]],
            [[false]; 6],
            [result.c1.b1.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
            ],
            [[false], [false], [false], [false], [false], [false]],
            [[c4.c1], [c4.c0], [c3.c1], [c3.c0], [c0.c1], [c0.c0]],
            [[false]; 6],
            [result.c1.b1.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
            ],
            [[false], [true], [false], [true], [false], [true]],
            [[c4.c0], [c4.c1], [c3.c0], [c3.c1], [c0.c0], [c0.c1]],
            [[false]; 6],
            [result.c1.b2.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
            ],
            [[false], [false], [false], [false], [false], [false]],
            [[c4.c1], [c4.c0], [c3.c1], [c3.c0], [c0.c1], [c0.c0]],
            [[false]; 6],
            [result.c1.b2.c1],
            [true],
        );
        result
    }

    /// Multiply by sparse element with coeffs in slots 3 and 4.
    pub fn mul_by_34(self, c3: Fp2, c4: Fp2) -> Fp12 {
        let a = self.c0;
        let b = self.c1.mul_by_01(c3, c4);
        let d0 = fp2_one().add(c3);
        let d = self.c0.add(self.c1).mul_by_01(d0, c4);

        let c1 = d.sub(a).sub(b);
        let c0 = b.mul_by_non_residue().add(a);

        Fp12 { c0, c1 }
    }

    /// Multiply by sparse element with coeffs in slots 0..4.
    unconstrained fn __mul_by_01234(self, x: [Fp2; 5]) -> Fp12 {
        let c0 = Fp6 { b0: x[0], b1: x[1], b2: x[2] };
        let c1 = Fp6 { b0: x[3], b1: x[4], b2: fp2_zero() };

        let a = self.c0.add(self.c1).mul(c0.add(c1));
        let b = self.c0.mul(c0);
        let c = self.c1.mul_by_01(x[3], x[4]);

        let c1 = a.sub(b).sub(c);
        let c0 = c.mul_by_non_residue().add(b);

        Fp12 { c0, c1 }
    }

    pub fn mul_by_01234(self, x: [Fp2; 5]) -> Fp12 {
        // Safety: twelve exact coefficient equations below constrain the entire hint.
        let result = unsafe { self.__mul_by_01234(x) };
        let scaled_1 = x[1].mul_by_element(fp_nine());
        let scaled_2 = x[2].mul_by_element(fp_nine());
        let scaled_3 = x[3].mul_by_element(fp_nine());
        let scaled_4 = x[4].mul_by_element(fp_nine());
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [true], [true], [false], [true], [true], [true],
                [false], [true], [true], [true], [false], [true], [true], [true],
            ],
            [
                [x[0].c0],
                [x[0].c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[2].c0],
                [scaled_2.c1],
                [scaled_1.c0],
                [x[1].c1],
                [x[1].c0],
                [scaled_1.c1],
                [scaled_4.c0],
                [x[4].c1],
                [x[4].c0],
                [scaled_4.c1],
                [scaled_3.c0],
                [x[3].c1],
                [x[3].c0],
                [scaled_3.c1],
            ],
            [[false]; 18],
            [result.c0.b0.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [true], [false], [false], [false],
                [true], [false], [false], [false], [true], [false], [false], [false], [true],
            ],
            [
                [x[0].c1],
                [x[0].c0],
                [x[2].c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[1].c0],
                [scaled_1.c1],
                [scaled_1.c0],
                [x[1].c1],
                [x[4].c0],
                [scaled_4.c1],
                [scaled_4.c0],
                [x[4].c1],
                [x[3].c0],
                [scaled_3.c1],
                [scaled_3.c0],
                [x[3].c1],
            ],
            [[false]; 18],
            [result.c0.b0.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [false], [true], [true], [true], [false], [true],
                [false], [true], [true], [true],
            ],
            [
                [x[1].c0],
                [x[1].c1],
                [x[0].c0],
                [x[0].c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[2].c0],
                [scaled_2.c1],
                [x[3].c0],
                [x[3].c1],
                [scaled_4.c0],
                [x[4].c1],
                [x[4].c0],
                [scaled_4.c1],
            ],
            [[false]; 14],
            [result.c0.b1.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [true], [false],
                [false], [false], [false], [false], [true],
            ],
            [
                [x[1].c1],
                [x[1].c0],
                [x[0].c1],
                [x[0].c0],
                [x[2].c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[3].c1],
                [x[3].c0],
                [x[4].c0],
                [scaled_4.c1],
                [scaled_4.c0],
                [x[4].c1],
            ],
            [[false]; 14],
            [result.c0.b1.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
            ],
            [[false], [true], [false], [true], [false], [true], [false], [true], [false], [true]],
            [
                [x[2].c0], [x[2].c1], [x[1].c0], [x[1].c1], [x[0].c0], [x[0].c1], [x[4].c0],
                [x[4].c1], [x[3].c0], [x[3].c1],
            ],
            [[false]; 10],
            [result.c0.b2.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [false], [false],
                [false],
            ],
            [
                [x[2].c1], [x[2].c0], [x[1].c1], [x[1].c0], [x[0].c1], [x[0].c0], [x[4].c1],
                [x[4].c0], [x[3].c1], [x[3].c0],
            ],
            [[false]; 10],
            [result.c0.b2.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [true], [true], [false], [true], [false], [true],
                [true], [true], [false], [true], [true], [true],
            ],
            [
                [x[3].c0],
                [x[3].c1],
                [scaled_4.c0],
                [x[4].c1],
                [x[4].c0],
                [scaled_4.c1],
                [x[0].c0],
                [x[0].c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[2].c0],
                [scaled_2.c1],
                [scaled_1.c0],
                [x[1].c1],
                [x[1].c0],
                [scaled_1.c1],
            ],
            [[false]; 16],
            [result.c1.b0.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [true], [false], [false], [false],
                [false], [false], [true], [false], [false], [false], [true],
            ],
            [
                [x[3].c1],
                [x[3].c0],
                [x[4].c0],
                [scaled_4.c1],
                [scaled_4.c0],
                [x[4].c1],
                [x[0].c1],
                [x[0].c0],
                [x[2].c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[1].c0],
                [scaled_1.c1],
                [scaled_1.c0],
                [x[1].c1],
            ],
            [[false]; 16],
            [result.c1.b0.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [false], [true], [false], [true], [false], [true],
                [true], [true],
            ],
            [
                [x[4].c0],
                [x[4].c1],
                [x[3].c0],
                [x[3].c1],
                [x[1].c0],
                [x[1].c1],
                [x[0].c0],
                [x[0].c1],
                [scaled_2.c0],
                [x[2].c1],
                [x[2].c0],
                [scaled_2.c1],
            ],
            [[false]; 12],
            [result.c1.b1.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [false], [false],
                [false], [false], [true],
            ],
            [
                [x[4].c1],
                [x[4].c0],
                [x[3].c1],
                [x[3].c0],
                [x[1].c1],
                [x[1].c0],
                [x[0].c1],
                [x[0].c0],
                [x[2].c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [x[2].c1],
            ],
            [[false]; 12],
            [result.c1.b1.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
            ],
            [[false], [true], [false], [true], [false], [true], [false], [true], [false], [true]],
            [
                [x[4].c0], [x[4].c1], [x[3].c0], [x[3].c1], [x[2].c0], [x[2].c1], [x[1].c0],
                [x[1].c1], [x[0].c0], [x[0].c1],
            ],
            [[false]; 10],
            [result.c1.b2.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [false], [false],
                [false],
            ],
            [
                [x[4].c1], [x[4].c0], [x[3].c1], [x[3].c0], [x[2].c1], [x[2].c0], [x[1].c1],
                [x[1].c0], [x[0].c1], [x[0].c0],
            ],
            [[false]; 10],
            [result.c1.b2.c1],
            [true],
        );
        result
    }

    pub fn square(self) -> Fp12 {
        // Safety: twelve exact coefficient equations below constrain the entire hint.
        let result = unsafe { self.__square() };
        let scaled_1 = self.c0.b1.mul_by_element(fp_nine());
        let scaled_2 = self.c0.b2.mul_by_element(fp_nine());
        let scaled_3 = self.c1.b0.mul_by_element(fp_nine());
        let scaled_4 = self.c1.b1.mul_by_element(fp_nine());
        let scaled_5 = self.c1.b2.mul_by_element(fp_nine());
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [true], [true], [false], [true], [true], [true],
                [false], [true], [true], [true], [false], [true], [true], [true], [false], [true],
                [true], [true],
            ],
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [scaled_1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c0],
                [scaled_1.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_4.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c0],
                [scaled_4.c1],
                [scaled_3.c0],
                [self.c1.b0.c1],
                [self.c1.b0.c0],
                [scaled_3.c1],
            ],
            [[false]; 22],
            [result.c0.b0.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [true], [false], [false], [false],
                [true], [false], [false], [false], [true], [false], [false], [false], [true],
                [false], [false], [false], [true],
            ],
            [
                [self.c0.b0.c1],
                [self.c0.b0.c0],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c0.b1.c0],
                [scaled_1.c1],
                [scaled_1.c0],
                [self.c0.b1.c1],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b1.c0],
                [scaled_4.c1],
                [scaled_4.c0],
                [self.c1.b1.c1],
                [self.c1.b0.c0],
                [scaled_3.c1],
                [scaled_3.c0],
                [self.c1.b0.c1],
            ],
            [[false]; 22],
            [result.c0.b0.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [false], [true], [true], [true], [false], [true],
                [false], [true], [true], [true], [false], [true], [true], [true],
            ],
            [
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_4.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c0],
                [scaled_4.c1],
            ],
            [[false]; 18],
            [result.c0.b1.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [true], [false],
                [false], [false], [false], [false], [true], [false], [false], [false], [true],
            ],
            [
                [self.c0.b1.c1],
                [self.c0.b1.c0],
                [self.c0.b0.c1],
                [self.c0.b0.c0],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c1],
                [self.c1.b0.c0],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b1.c0],
                [scaled_4.c1],
                [scaled_4.c0],
                [self.c1.b1.c1],
            ],
            [[false]; 18],
            [result.c0.b1.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [false], [true], [false], [true], [false], [true],
                [false], [true], [true], [true],
            ],
            [
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c0],
                [scaled_5.c1],
            ],
            [[false]; 14],
            [result.c0.b2.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [false], [false],
                [false], [false], [false], [false], [true],
            ],
            [
                [self.c0.b2.c1],
                [self.c0.b2.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c0],
                [self.c0.b0.c1],
                [self.c0.b0.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c0],
                [self.c1.b0.c1],
                [self.c1.b0.c0],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
            ],
            [[false]; 14],
            [result.c0.b2.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [true], [true], [false], [true], [true], [true],
                [false], [true], [false], [true], [true], [true], [false], [true], [true], [true],
            ],
            [
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_4.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c0],
                [scaled_4.c1],
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [scaled_1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c0],
                [scaled_1.c1],
            ],
            [[false]; 20],
            [result.c1.b0.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [true], [false], [false], [false],
                [true], [false], [false], [false], [false], [false], [true], [false], [false],
                [false], [true],
            ],
            [
                [self.c1.b0.c1],
                [self.c1.b0.c0],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b1.c0],
                [scaled_4.c1],
                [scaled_4.c0],
                [self.c1.b1.c1],
                [self.c0.b0.c1],
                [self.c0.b0.c0],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c0.b1.c0],
                [scaled_1.c1],
                [scaled_1.c0],
                [self.c0.b1.c1],
            ],
            [[false]; 20],
            [result.c1.b0.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [false], [true], [true], [true], [false], [true],
                [false], [true], [false], [true], [true], [true],
            ],
            [
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c0],
                [scaled_2.c1],
            ],
            [[false]; 16],
            [result.c1.b1.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [true], [false],
                [false], [false], [false], [false], [false], [false], [true],
            ],
            [
                [self.c1.b1.c1],
                [self.c1.b1.c0],
                [self.c1.b0.c1],
                [self.c1.b0.c0],
                [self.c1.b2.c0],
                [scaled_5.c1],
                [scaled_5.c0],
                [self.c1.b2.c1],
                [self.c0.b1.c1],
                [self.c0.b1.c0],
                [self.c0.b0.c1],
                [self.c0.b0.c0],
                [self.c0.b2.c0],
                [scaled_2.c1],
                [scaled_2.c0],
                [self.c0.b2.c1],
            ],
            [[false]; 16],
            [result.c1.b1.c1],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
            ],
            [
                [false], [true], [false], [true], [false], [true], [false], [true], [false], [true],
                [false], [true],
            ],
            [
                [self.c1.b2.c0],
                [self.c1.b2.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b0.c0],
                [self.c0.b0.c1],
            ],
            [[false]; 12],
            [result.c1.b2.c0],
            [true],
        );
        evaluate_quadratic_expression(
            [
                [self.c0.b0.c0],
                [self.c0.b0.c1],
                [self.c0.b1.c0],
                [self.c0.b1.c1],
                [self.c0.b2.c0],
                [self.c0.b2.c1],
                [self.c1.b0.c0],
                [self.c1.b0.c1],
                [self.c1.b1.c0],
                [self.c1.b1.c1],
                [self.c1.b2.c0],
                [self.c1.b2.c1],
            ],
            [
                [false], [false], [false], [false], [false], [false], [false], [false], [false],
                [false], [false], [false],
            ],
            [
                [self.c1.b2.c1],
                [self.c1.b2.c0],
                [self.c1.b1.c1],
                [self.c1.b1.c0],
                [self.c1.b0.c1],
                [self.c1.b0.c0],
                [self.c0.b2.c1],
                [self.c0.b2.c0],
                [self.c0.b1.c1],
                [self.c0.b1.c0],
                [self.c0.b0.c1],
                [self.c0.b0.c0],
            ],
            [[false]; 12],
            [result.c1.b2.c1],
            [true],
        );
        result
    }

    /// Exponentiation by (x) and its powers in the cyclotomic subgroup.
    /// Uses a fixed addition chain tailored to BN254 (Fuentes-Castaneda et al. 2011).
    pub fn expt(self) -> Fp12 {
        let x = self;
        let t3 = x.cyclotomic_square();
        let t5 = t3.cyclotomic_square();
        let result = t5.cyclotomic_square();
        let t0 = result.cyclotomic_square();
        let t2 = x.mul(t0);
        let t0 = t3.mul(t2);
        let t1 = x.mul(t0);
        let t4 = result.mul(t2);
        let t6 = t2.cyclotomic_square();
        let t1 = t0.mul(t1);
        let t0 = t3.mul(t1);
        let t6 = t6.n_square(6);
        let t5 = t5.mul(t6);
        let t5 = t4.mul(t5);
        let t5 = t5.n_square(7);
        let t4 = t4.mul(t5);
        let t4 = t4.n_square(8);
        let t4 = t4.mul(t0);
        let t3 = t3.mul(t4);
        let t3 = t3.n_square(6);
        let t2 = t2.mul(t3);
        let t2 = t2.n_square(8);
        let t2 = t2.mul(t0);
        let t2 = t2.n_square(6);
        let t2 = t2.mul(t0);
        let t2 = t2.n_square(10);
        let t1 = t1.mul(t2);
        let t1 = t1.n_square(6);
        let t0 = t0.mul(t1);
        let result = result.mul(t0);
        result
    }

    /// Repeated cyclotomic squaring.
    pub fn n_square(self, n: u32) -> Fp12 {
        let mut result = self;
        for _ in 0..n {
            result = result.cyclotomic_square();
        }
        result
    }
}

/// Multiply two sparse line evaluations (coeffs 0,3,4) into 5-slot form.
pub fn mul_034_by_034(d0: Fp2, d3: Fp2, d4: Fp2, c0: Fp2, c3: Fp2, c4: Fp2) -> [Fp2; 5] {
    let x0 = c0.mul(d0);
    let x3 = c3.mul(d3);
    let x4 = c4.mul(d4);

    let x04 = (c0.add(c4)).mul(d0.add(d4)).sub(x0).sub(x4);
    let x03 = (c0.add(c3)).mul(d0.add(d3)).sub(x0).sub(x3);
    let x34 = (c3.add(c4)).mul(d3.add(d4)).sub(x3).sub(x4);

    let z00 = x4.mul_by_non_residue().add(x0);
    [z00, x3, x34, x03, x04]
}
