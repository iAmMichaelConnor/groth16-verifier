//! Tower-arithmetic tests: the Fp6 multiplication against its defining relation
//! v^3 = 9 + u. The heavier Fp6 and Fp12 tests, which pin the sparse and
//! specialised routines against the general multiplication and the Fp12
//! multiplication against w^2 = v, are in the sibling bn254_fields_slow_tests
//! package. No hinted value is trusted: every product below is the constrained
//! result.
//!
//! The `random_` tests take their operands from nargo's fuzzer and check the
//! same relations, and the Frobenius and cyclotomic identities, on random
//! elements. They are `unconstrained`, so they check results, not constraints.
use crate::fp::{Fp, fp_zero};
use crate::fp12::{Fp12, fp12_zero, mul_034_by_034};
use crate::fp2::{Fp2, fp2_one, fp2_zero, non_residue};
use crate::fp6::{Fp6, fp6_one, fp6_zero};

fn e2(a: Field, b: Field) -> Fp2 {
    Fp2 { c0: Fp::from(a), c1: Fp::from(b) }
}

fn e6(seed: Field) -> Fp6 {
    Fp6 { b0: e2(seed + 1, seed + 2), b1: e2(seed + 3, seed + 5), b2: e2(seed + 8, seed + 13) }
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

// Tower elements from fuzzer input, two coefficients per Fp2 starting at x[i].
fn r2<let N: u32>(x: [Field; N], i: u32) -> Fp2 {
    e2(x[i], x[i + 1])
}

fn r6<let N: u32>(x: [Field; N], i: u32) -> Fp6 {
    Fp6 { b0: r2(x, i), b1: r2(x, i + 2), b2: r2(x, i + 4) }
}

fn r12(x: [Field; 12]) -> Fp12 {
    Fp12 { c0: r6(x, 0), c1: r6(x, 6) }
}

#[test]
fn fp6_reduces_by_v_cubed_equals_xi() {
    let v = Fp6 { b0: fp2_zero(), b1: fp2_one(), b2: fp2_zero() };
    let v2 = Fp6 { b0: fp2_zero(), b1: fp2_zero(), b2: fp2_one() };
    let xi = Fp6 { b0: non_residue(), b1: fp2_zero(), b2: fp2_zero() };
    assert(eq6(v.mul(v), v2));
    assert(eq6(v.mul(v2), xi));
    assert(eq6(v2.mul_by_non_residue(), xi));
    assert(eq6(e6(1).mul(fp6_one()), e6(1)));
}

#[test]
unconstrained fn random_fp2_and_fp6_routines_match_general_mul(x: [Field; 6], y: [Field; 6]) {
    let a = r2(x, 0);
    let b = r2(y, 0);
    assert(eq2(a.mul(b), b.mul(a)));
    assert(eq2(a.mul_by_non_residue(), a.mul(non_residue())));
    assert(
        eq2(
            a.mul_by_element(b.c0),
            a.mul(Fp2 { c0: b.c0, c1: fp_zero() }),
        ),
    );
    assert(eq2(a.halve().double(), a));
    if !eq2(a, fp2_zero()) {
        assert(eq2(a.mul(a.inverse()), fp2_one()));
    }

    let a = r6(x, 0);
    let b = r6(y, 0);
    let (c0, c1) = (r2(y, 0), r2(y, 2));
    let v = Fp6 { b0: fp2_zero(), b1: fp2_one(), b2: fp2_zero() };
    assert(eq6(a.mul(b), b.mul(a)));
    assert(eq6(a.mul(b.add(a)), a.mul(b).add(a.mul(a))));
    assert(eq6(a.mul_by_non_residue(), a.mul(v)));
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
    if !eq6(a, fp6_zero()) {
        assert(eq6(a.mul(a.inverse()), fp6_one()));
    }
}

#[test]
unconstrained fn random_fp12_routines_match_general_mul(x: [Field; 12], y: [Field; 12]) {
    let a = r12(x);
    let b = r12(y);
    // The fuzzer's first input is all zeros, and it stops after that round if
    // the round took over its time limit, so the zero element is skipped.
    if !eq12(a, fp12_zero()) {
        assert(eq12(a.square(), a.mul(a)));
        assert(eq12(a.mul(b), b.mul(a)));
        assert(eq12(a.mul(b.add(a)), a.mul(b).add(a.square())));
        assert(a.mul(a.inverse()).is_one());

        let (c0, c3, c4) = (r2(y, 0), r2(y, 2), r2(y, 4));
        let (d0, d3, d4) = (r2(y, 6), r2(y, 8), r2(y, 10));
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
        let p = mul_034_by_034(d0, d3, d4, c0, c3, c4);
        let dense = Fp12 {
            c0: Fp6 { b0: p[0], b1: p[1], b2: p[2] },
            c1: Fp6 { b0: p[3], b1: p[4], b2: fp2_zero() },
        };
        assert(eq12(dense, line.mul(other)));
        assert(eq12(a.mul_by_01234(p), a.mul(dense)));
    }
}

#[test]
unconstrained fn random_fp12_frobenius_and_cyclotomic_identities(x: [Field; 12], y: [Field; 12]) {
    let a = r12(x);
    let b = r12(y);
    assert(eq12(a.mul(b).frobenius(), a.frobenius().mul(b.frobenius())));
    assert(eq12(a.frobenius().frobenius(), a.frobenius_square()));
    assert(eq12(a.frobenius_square().frobenius(), a.frobenius_cube()));
    // Frobenius^6 fixes Fp6 and maps w to -w.
    assert(eq12(a.frobenius_cube().frobenius_cube(), a.conjugate()));

    if !eq12(a, fp12_zero()) {
        // u = a^((p^6 - 1)(p^2 + 1)) lies in the cyclotomic subgroup.
        let t = a.conjugate().mul(a.inverse());
        let u = t.frobenius_square().mul(t);
        assert(u.mul(u.conjugate()).is_one());
        assert(eq12(u.cyclotomic_square(), u.square()));
        assert(eq12(u.n_square(3), u.square().square().square()));
    }
}
