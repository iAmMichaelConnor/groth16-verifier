// Benchmark entry point: Jacobian G2 doubling. The input is a canonical affine
// point checked to be on the twist (no subgroup check); the output coordinates
// are reduced to canonical form, so the count includes those checks.
// `nargo export` compiles it to its own program for the gates report.
use crate::BigNum;
use crate::fp::{Fp, fp_from_limbs_checked};
use crate::fp2::Fp2;
use crate::g2::{double_g2_jac, g2_affine_to_jacobian, G2Affine, is_on_curve_g2_affine};

fn read_fp2(a: [u128; 3], b: [u128; 3]) -> Fp2 {
    Fp2 { c0: fp_from_limbs_checked(a), c1: fp_from_limbs_checked(b) }
}

fn write_fp(a: Fp) -> [u128; 3] {
    a.validate_in_field();
    a.get_limbs()
}

#[export]
fn bn254_g2_double(a: [[u128; 3]; 4]) -> [[u128; 3]; 6] {
    let p = G2Affine { x: read_fp2(a[0], a[1]), y: read_fp2(a[2], a[3]) };
    assert(is_on_curve_g2_affine(p));
    let r = double_g2_jac(g2_affine_to_jacobian(p));
    [
        write_fp(r.x.c0),
        write_fp(r.x.c1),
        write_fp(r.y.c0),
        write_fp(r.y.c1),
        write_fp(r.z.c0),
        write_fp(r.z.c1),
    ]
}
