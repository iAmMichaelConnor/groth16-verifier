//! Tower-arithmetic tests of bn254_fields that each compile to a large circuit,
//! so the nightly constrained run handles them one test at a time. Sparse and
//! specialised routines are pinned against the general multiplication; the Fp12
//! multiplication is pinned against the defining relation w^2 = v. No hinted
//! value is trusted: every product below is the constrained result.
use fields::fp::Fp;
use fields::fp12::{Fp12, fp12_one, mul_034_by_034};
use fields::fp2::{Fp2, fp2_one, fp2_zero};
use fields::fp6::{Fp6, fp6_one, fp6_zero};

fn e2(a: Field, b: Field) -> Fp2 {
    Fp2 { c0: Fp::from(a), c1: Fp::from(b) }
}

fn e6(seed: Field) -> Fp6 {
    Fp6 { b0: e2(seed + 1, seed + 2), b1: e2(seed + 3, seed + 5), b2: e2(seed + 8, seed + 13) }
}

fn e12(seed: Field) -> Fp12 {
    Fp12 { c0: e6(seed), c1: e6(seed + 21) }
}

fn eq2(a: Fp2, b: Fp2) -> bool {
    (a.c0 == b.c0) & (a.c1 == b.c1)
}

fn eq6(a: Fp6, b: Fp6) -> bool {
    eq2(a.b0, b.b0) & eq2(a.b1, b.b1) & eq2(a.b2, b.b2)
}

fn eq12(a: Fp12, b: Fp12) -> bool {
    eq6(a.c0, b.c0) & eq6(a.c1, b.c1)
}

#[test]
fn fp6_inverse_and_sparse_products_match_general_mul() {
    let a = e6(1);
    let c0 = e2(34, 55);
    let c1 = e2(89, 144);
    assert(eq6(a.mul(a.inverse()), fp6_one()));
    assert(eq6(a.square(), a.mul(a)));
    assert(
        eq6(
            a.mul_by_e2(c0),
            a.mul(Fp6 { b0: c0, b1: fp2_zero(), b2: fp2_zero() }),
        ),
    );
    assert(
        eq6(
            a.mul_by_01(c0, c1),
            a.mul(Fp6 { b0: c0, b1: c1, b2: fp2_zero() }),
        ),
    );
    assert(
        eq6(
            a.mul_by_1(c1),
            a.mul(Fp6 { b0: fp2_zero(), b1: c1, b2: fp2_zero() }),
        ),
    );
    assert(
        eq6(
            a.mul_by_12(c0, c1),
            a.mul(Fp6 { b0: fp2_zero(), b1: c0, b2: c1 }),
        ),
    );
}

#[test]
fn fp12_reduces_by_w_squared_equals_v() {
    let w = Fp12 { c0: fp6_zero(), c1: fp6_one() };
    let v = Fp12 { c0: Fp6 { b0: fp2_zero(), b1: fp2_one(), b2: fp2_zero() }, c1: fp6_zero() };
    assert(eq12(w.mul(w), v));
    assert(eq12(w.square(), v));
    assert(eq12(e12(1).mul(fp12_one()), e12(1)));
    assert(fp12_one().is_one());
    assert(!w.is_one());
}

#[test]
fn fp12_square_and_inverse_match_general_mul() {
    let a = e12(1);
    assert(eq12(a.square(), a.mul(a)));
    assert(a.mul(a.inverse()).is_one());
}

#[test]
fn fp12_sparse_products_match_general_mul() {
    let a = e12(1);
    let c0 = e2(2, 7);
    let c3 = e2(34, 55);
    let c4 = e2(89, 144);
    let d0 = e2(3, 11);
    let d3 = e2(233, 377);
    let d4 = e2(610, 987);
    let line = Fp12 {
        c0: Fp6 { b0: c0, b1: fp2_zero(), b2: fp2_zero() },
        c1: Fp6 { b0: c3, b1: c4, b2: fp2_zero() },
    };
    let other = Fp12 {
        c0: Fp6 { b0: d0, b1: fp2_zero(), b2: fp2_zero() },
        c1: Fp6 { b0: d3, b1: d4, b2: fp2_zero() },
    };
    let normalised = Fp12 { c0: fp6_one(), c1: Fp6 { b0: c3, b1: c4, b2: fp2_zero() } };
    assert(eq12(a.mul_by_034(c0, c3, c4), a.mul(line)));
    assert(eq12(a.mul_by_34(c3, c4), a.mul(normalised)));
    let x = mul_034_by_034(d0, d3, d4, c0, c3, c4);
    let dense = Fp12 {
        c0: Fp6 { b0: x[0], b1: x[1], b2: x[2] },
        c1: Fp6 { b0: x[3], b1: x[4], b2: fp2_zero() },
    };
    assert(eq12(dense, line.mul(other)));
    assert(eq12(a.mul_by_01234(x), a.mul(dense)));
}

#[test]
fn fp12_frobenius_maps_are_consistent_field_automorphisms() {
    let a = e12(1);
    let b = e12(100);
    // Multiplicative, so the per-slot coefficients are powers of one generator.
    assert(eq12(a.mul(b).frobenius(), a.frobenius().mul(b.frobenius())));
    // The three maps are the first three powers of the same automorphism.
    assert(eq12(a.frobenius().frobenius(), a.frobenius_square()));
    assert(eq12(a.frobenius_square().frobenius(), a.frobenius_cube()));
    // Frobenius^12 is the identity on Fp12.
    let mut x = a;
    for _ in 0..6 {
        x = x.frobenius_square();
    }
    assert(eq12(x, a));
}

#[test]
fn fp12_cyclotomic_square_matches_square_in_the_cyclotomic_subgroup() {
    // u = a^((p^6 - 1)(p^2 + 1)) lies in the cyclotomic subgroup, where the
    // inverse is the conjugate and the compressed squaring formula is valid.
    let a = e12(1);
    let t = a.conjugate().mul(a.inverse());
    let u = t.frobenius_square().mul(t);
    assert(u.mul(u.conjugate()).is_one());
    assert(eq12(u.cyclotomic_square(), u.square()));
    assert(eq12(u.n_square(2), u.square().square()));
}
