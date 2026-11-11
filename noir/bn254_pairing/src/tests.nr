//! Pairing tests, all `unconstrained`: they check the values `pairing` and
//! `pairing_multi` compute, not the constraints (constrained, a pairing test
//! needs tens of GB to compile). The scalars are fixed: nargo's fuzzer runs at
//! least nine inputs, twice each, and a fuzzed pairing input took about a
//! minute.
use crate::fp::{Fp, fp_from_limbs_checked, fp_one, fp_two};
use crate::fp12::{Fp12, fp12_one};
use crate::fp2::Fp2;
use crate::fp6::Fp6;
use crate::g1::{
    add_g1_jac, double_g1_jac, g1_jacobian_infinity, G1Affine, G1Jac, jacobian_to_affine_g1,
};
use crate::g2::{g2_affine_to_jacobian, G2Affine, jacobian_to_affine_g2, scalar_mul_g2_by_u128};
use crate::{pairing, pairing_multi};

fn fp(limbs: [u128; 3]) -> Fp {
    fp_from_limbs_checked(limbs)
}

fn g1() -> G1Affine {
    G1Affine { x: fp_one(), y: fp_two() }
}

fn g2() -> G2Affine {
    G2Affine {
        x: Fp2 {
            c0: fp(
                [0x4322d4f75edadd46debd5cd992f6ed, 0xdeef121f1e76426a00665e5c447967, 0x1800],
            ),
            c1: fp(
                [0xaa493335a9e71297e485b7aef312c2, 0x9393920d483a7260bfb731fb5d25f1, 0x198e],
            ),
        },
        y: Fp2 {
            c0: fp(
                [0xd1e7690c43d37b4ce6cc0166fa7daa, 0x5ea5db8c6deb4aab71808dcb408fe3, 0x12c8],
            ),
            c1: fp(
                [0x4b313370b38ef355acdadcd122975b, 0x89d0585ff075ec9e99ad690c3395bc, 0x906],
            ),
        },
    }
}

// e(G1, G2) as @noble/curves 1.7.0 (a dependency of the hint SDK) computes it,
// coefficients in the order c0.b0.c0, c0.b0.c1, ..., c1.b2.c1. Both it and this
// package return the canonical pairing value to the power k = 2x(6x^2 + 3x + 1),
// the multiple their final-exponentiation addition chains compute.
fn e_g1_g2() -> Fp12 {
    Fp12 {
        c0: Fp6 {
            b0: Fp2 {
                c0: fp([0x7e5feb898578b55e1f63739d870e95, 0x253feda94cfe0da01bde280a3ed6f8, 0x262b]),
                c1: fp(
                    [0x7c4dea0918ed66b49d34b48efb8a4a, 0x2d2cc795a2000a1b1f823879abbd39, 0x2e0],
                ),
            },
            b1: Fp2 {
                c0: fp([0xd2957387ecb1fc4e135402fdbd1de0, 0xf2d6e29b128da5b1ad44b31977935f, 0x13a9]),
                c1: fp(
                    [0xb420bd699ce630b130b08a6ea1162b, 0xa9fa500f1a5c4b31984a74e68659c4, 0x40b],
                ),
            },
            b2: Fp2 {
                c0: fp(
                    [0x8f590b211ce30bf5e3eeaef89eafdb, 0x2f3fd870678fbe359d7f9873f05247, 0xafc],
                ),
                c1: fp([0xa9a712cc5a8243f9cddbd2d98dd1f0, 0xa530398c9064bdc662d929e645cadd, 0x1c54]),
            },
        },
        c1: Fp6 {
            b0: Fp2 {
                c0: fp(
                    [0xa990ecfd4b7aef5c0d58c5dc2429fe, 0xfbf5d5a1ac023794a0d856f92591b, 0x95c],
                ),
                c1: fp([0xad9ebb590cb4a60f8215d4b99f2b4a, 0xd6ca72d8a950a31dc10f7b4053c9e9, 0x14d3]),
            },
            b1: Fp2 {
                c0: fp([0xdc1a23043c585fdfaf545838ca7429, 0xe7bbc3d70e6689dc206b4b91c85759, 0x1dc0]),
                c1: fp(
                    [0xb90d61ac16cc1b7ab2cd3ed5e22b97, 0x320e5a6488cb98a855ffc837d2a75a, 0xb53],
                ),
            },
            b2: Fp2 {
                c0: fp([0xce07bac42a9c0f9bd7fddaf5ebd723, 0xafd3085dae4c6c91476ef36cd1d318, 0x13a8]),
                c1: fp(
                    [0xeee1b343940c383e5314859e762c97, 0x7b5221474526b601f3730a3afa965c, 0xf9],
                ),
            },
        },
    }
}

fn eq2(a: Fp2, b: Fp2) -> bool {
    (a.c0 == b.c0) & (a.c1 == b.c1)
}

fn eq12(a: Fp12, b: Fp12) -> bool {
    eq2(a.c0.b0, b.c0.b0)
        & eq2(a.c0.b1, b.c0.b1)
        & eq2(a.c0.b2, b.c0.b2)
        & eq2(a.c1.b0, b.c1.b0)
        & eq2(a.c1.b1, b.c1.b1)
        & eq2(a.c1.b2, b.c1.b2)
}

fn g1_mul(p: G1Affine, k: u128) -> G1Affine {
    let mut acc = g1_jacobian_infinity();
    let mut base = G1Jac { x: p.x, y: p.y, z: fp_one() };
    let mut k = k;
    for _ in 0..128 {
        if (k & 1) == 1 {
            acc = add_g1_jac(acc, base);
        }
        base = double_g1_jac(base);
        k = k >> 1;
    }
    jacobian_to_affine_g1(acc)
}

fn g2_mul(q: G2Affine, k: u128) -> G2Affine {
    jacobian_to_affine_g2(scalar_mul_g2_by_u128(g2_affine_to_jacobian(q), k))
}

// Square-and-multiply in the cyclotomic subgroup, where pairing values lie.
unconstrained fn gt_pow(a: Fp12, e: u128) -> Fp12 {
    let mut acc = fp12_one();
    let mut base = a;
    let mut k = e;
    for _ in 0..128 {
        if k != 0 {
            if (k & 1) == 1 {
                acc = acc.mul(base);
            }
            base = base.cyclotomic_square();
            k = k >> 1;
        }
    }
    acc
}

#[test]
unconstrained fn e_g1_g2_matches_reference_and_has_order_r() {
    let e = pairing(g1(), g2());
    assert(eq12(e, e_g1_g2()));
    assert(!e.is_one());
    // r = 2^128 r_hi + r_lo.
    let r_hi: u128 = 0x30644e72e131a029b85045b68181585d;
    let r_lo: u128 = 0x2833e84879b9709143e1f593f0000001;
    assert(gt_pow(e, r_hi).n_square(128).mul(gt_pow(e, r_lo)).is_one());
}

#[test]
unconstrained fn pairing_is_bilinear() {
    let a: u128 = 0x9e3779b97f4a7c15;
    let (p, q) = (g1(), g2());
    let e_a = gt_pow(e_g1_g2(), a);
    assert(eq12(pairing(g1_mul(p, a), q), e_a));
    assert(eq12(pairing(p, g2_mul(q, a)), e_a));
}

// A separate test, so that its two-pair Miller loop compiles in parallel with
// the single-pair one.
#[test]
unconstrained fn pairing_multi_is_the_product_of_pairings() {
    let a: u128 = 0x7f4a7c15f39cc060;
    let (p, q) = (g1(), g2());
    // e(aP, Q) * e(P, aQ) = e(P, Q)^(2a).
    let product = pairing_multi([g1_mul(p, a), p], [q, g2_mul(q, a)]);
    assert(eq12(product, gt_pow(e_g1_g2(), 2 * a)));
}
