// Benchmark entry point: affine G1 addition. Inputs are canonical Fq
// coordinates checked to be on the curve; the output is reduced to canonical
// form, so the count includes those checks. `nargo export` compiles it to its
// own program for the gates report.
use crate::BigNum;
use crate::fp::{Fp, fp_from_limbs_checked};
use crate::g1::{add_g1_affine, G1Affine, is_on_curve_g1_affine};

fn read_g1(a: [[u128; 3]; 2]) -> G1Affine {
    let p = G1Affine { x: fp_from_limbs_checked(a[0]), y: fp_from_limbs_checked(a[1]) };
    assert(is_on_curve_g1_affine(p));
    p
}

fn write_fp(a: Fp) -> [u128; 3] {
    a.validate_in_field();
    a.get_limbs()
}

#[export]
fn bn254_g1_add(a: [[u128; 3]; 2], b: [[u128; 3]; 2]) -> [[u128; 3]; 2] {
    let r = add_g1_affine(read_g1(a), read_g1(b));
    [write_fp(r.x), write_fp(r.y)]
}
