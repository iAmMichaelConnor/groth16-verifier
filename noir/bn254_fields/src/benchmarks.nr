// Benchmark entry points: one #[export] function per operation. Inputs are
// range-checked canonical Fq coefficients and outputs are reduced to canonical
// form, so each count includes those checks. `nargo export` compiles each
// function to its own program for the gates report.
use crate::{BigNum, Fp, Fp12, Fp2, Fp6};
use crate::fp::fp_from_limbs_checked;

fn read_fp2(a: [[u128; 3]; 2]) -> Fp2 {
    Fp2 { c0: fp_from_limbs_checked(a[0]), c1: fp_from_limbs_checked(a[1]) }
}

fn read_fp6(a: [[u128; 3]; 6]) -> Fp6 {
    Fp6 { b0: read_fp2([a[0], a[1]]), b1: read_fp2([a[2], a[3]]), b2: read_fp2([a[4], a[5]]) }
}

fn read_fp12(a: [[u128; 3]; 12]) -> Fp12 {
    Fp12 {
        c0: read_fp6([a[0], a[1], a[2], a[3], a[4], a[5]]),
        c1: read_fp6([a[6], a[7], a[8], a[9], a[10], a[11]]),
    }
}

fn write_fp(a: Fp) -> [u128; 3] {
    a.validate_in_field();
    a.get_limbs()
}

fn write_fp2(a: Fp2) -> [[u128; 3]; 2] {
    [write_fp(a.c0), write_fp(a.c1)]
}

fn write_fp6(a: Fp6) -> [[u128; 3]; 6] {
    let b0 = write_fp2(a.b0);
    let b1 = write_fp2(a.b1);
    let b2 = write_fp2(a.b2);
    [b0[0], b0[1], b1[0], b1[1], b2[0], b2[1]]
}

fn write_fp12(a: Fp12) -> [[u128; 3]; 12] {
    let c0 = write_fp6(a.c0);
    let c1 = write_fp6(a.c1);
    [c0[0], c0[1], c0[2], c0[3], c0[4], c0[5], c1[0], c1[1], c1[2], c1[3], c1[4], c1[5]]
}

#[export]
fn bn254_fp_mul(a: [u128; 3], b: [u128; 3]) -> [u128; 3] {
    write_fp(fp_from_limbs_checked(a) * fp_from_limbs_checked(b))
}

#[export]
fn bn254_fp2_mul(a: [[u128; 3]; 2], b: [[u128; 3]; 2]) -> [[u128; 3]; 2] {
    write_fp2(read_fp2(a).mul(read_fp2(b)))
}

#[export]
fn bn254_fp6_mul(a: [[u128; 3]; 6], b: [[u128; 3]; 6]) -> [[u128; 3]; 6] {
    write_fp6(read_fp6(a).mul(read_fp6(b)))
}

#[export]
fn bn254_fp12_mul(a: [[u128; 3]; 12], b: [[u128; 3]; 12]) -> [[u128; 3]; 12] {
    write_fp12(read_fp12(a).mul(read_fp12(b)))
}
