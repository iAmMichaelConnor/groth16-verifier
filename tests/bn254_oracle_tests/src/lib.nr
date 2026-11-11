//! Differential tests of the BN254 tower arithmetic and pairing against
//! @noble/curves, which the oracle server in this directory runs (`run.sh`
//! starts it and runs these tests). Without the server every test fails, so no
//! other test run selects this package.
//!
//! The tower tests take their operands from nargo's fuzzer. The pairing tests
//! take random points and Fp12 elements from the oracle instead: a fuzzed
//! pairing input took about a minute. All are `unconstrained`: they compare
//! values, not constraints. `miller_loop` is not compared on its own: the
//! reference's Miller loop value differs from this one, and the two agree only
//! after the final exponentiation.
use bn254_pairing::{final_exponentiation, pairing, pairing_multi};
use bn254_pairing::fp::Fp;
use bn254_pairing::fp12::{Fp12, fp12_zero};
use bn254_pairing::fp2::{Fp2, fp2_zero};
use bn254_pairing::fp6::{Fp6, fp6_zero};
use bn254_pairing::g1::G1Affine;
use bn254_pairing::g2::G2Affine;

/// [a * b, a^2, a^-1], with zero for the inverse of zero.
#[oracle(fp2_reference)]
unconstrained fn fp2_reference(a: Fp2, b: Fp2) -> [Fp2; 3] {}

#[oracle(fp6_reference)]
unconstrained fn fp6_reference(a: Fp6, b: Fp6) -> [Fp6; 3] {}

/// [a * b, a^2, a^-1, a^p, a^(p^2), a^(p^3)], with zero for the inverse of zero.
#[oracle(fp12_reference)]
unconstrained fn fp12_reference(a: Fp12, b: Fp12) -> [Fp12; 6] {}

// Struct results come back as one-element arrays: an array result is one flat
// list of fields, a struct result one list per field.

/// A random multiple of the generator.
#[oracle(random_g1)]
unconstrained fn random_g1() -> [G1Affine; 1] {}

#[oracle(random_g2)]
unconstrained fn random_g2() -> [G2Affine; 1] {}

#[oracle(random_fp12)]
unconstrained fn random_fp12() -> [Fp12; 1] {}

/// prod_i e(p[i], q[i]).
#[oracle(pairing_reference)]
unconstrained fn pairing_reference<let N: u32>(p: [G1Affine; N], q: [G2Affine; N]) -> [Fp12; 1] {}

#[oracle(final_exponentiation_reference)]
unconstrained fn final_exponentiation_reference(f: Fp12) -> [Fp12; 1] {}

fn e2(a: Field, b: Field) -> Fp2 {
    Fp2 { c0: Fp::from(a), c1: Fp::from(b) }
}

fn r6<let N: u32>(x: [Field; N], i: u32) -> Fp6 {
    Fp6 { b0: e2(x[i], x[i + 1]), b1: e2(x[i + 2], x[i + 3]), b2: e2(x[i + 4], x[i + 5]) }
}

fn r12(x: [Field; 12]) -> Fp12 {
    Fp12 { c0: r6(x, 0), c1: r6(x, 6) }
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
unconstrained fn fp2_and_fp6_match_reference(x: [Field; 6], y: [Field; 6]) {
    let (a, b) = (e2(x[0], x[1]), e2(y[0], y[1]));
    let expected = fp2_reference(a, b);
    assert(eq2(a.mul(b), expected[0]));
    assert(eq2(a.square(), expected[1]));
    if !eq2(a, fp2_zero()) {
        assert(eq2(a.inverse(), expected[2]));
    }

    let (a, b) = (r6(x, 0), r6(y, 0));
    let expected = fp6_reference(a, b);
    assert(eq6(a.mul(b), expected[0]));
    assert(eq6(a.square(), expected[1]));
    if !eq6(a, fp6_zero()) {
        assert(eq6(a.inverse(), expected[2]));
    }
}

#[test]
unconstrained fn fp12_matches_reference(x: [Field; 12], y: [Field; 12]) {
    let (a, b) = (r12(x), r12(y));
    // The fuzzer's first input is all zeros, and it stops after that round if
    // the round took over its time limit, so the zero element is skipped.
    if !eq12(a, fp12_zero()) {
        let expected = fp12_reference(a, b);
        assert(eq12(a.mul(b), expected[0]));
        assert(eq12(a.square(), expected[1]));
        assert(eq12(a.inverse(), expected[2]));
        assert(eq12(a.frobenius(), expected[3]));
        assert(eq12(a.frobenius_square(), expected[4]));
        assert(eq12(a.frobenius_cube(), expected[5]));
        // The sparse line product against the reference's general product.
        let (c0, c3, c4) = (b.c0.b0, b.c1.b0, b.c1.b1);
        let line = Fp12 {
            c0: Fp6 { b0: c0, b1: fp2_zero(), b2: fp2_zero() },
            c1: Fp6 { b0: c3, b1: c4, b2: fp2_zero() },
        };
        assert(eq12(a.mul_by_034(c0, c3, c4), fp12_reference(a, line)[0]));
    }
}

#[test]
unconstrained fn pairing_and_final_exponentiation_match_reference() {
    let (p, q) = (random_g1()[0], random_g2()[0]);
    assert(eq12(pairing(p, q), pairing_reference([p], [q])[0]));
    let f = random_fp12()[0];
    assert(
        eq12(
            final_exponentiation(f),
            final_exponentiation_reference(f)[0],
        ),
    );
}

// A separate test, so that its two-pair Miller loop compiles in parallel with
// the single-pair one.
#[test]
unconstrained fn pairing_multi_matches_reference() {
    let p = [random_g1()[0], random_g1()[0]];
    let q = [random_g2()[0], random_g2()[0]];
    assert(eq12(pairing_multi(p, q), pairing_reference(p, q)[0]));
}
