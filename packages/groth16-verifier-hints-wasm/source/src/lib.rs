//! Standalone experimental residue kernel; no prover, SRS, or MPC dependency.
use ark_bn254::{Bn254, Fq, Fq12, Fq2, Fq6};
use ark_ec::pairing::{MillerLoopOutput, Pairing};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use num_bigint::{BigInt, BigUint, Sign};

use std::sync::OnceLock;
fn pow(a: Fq12, n: &BigUint) -> Fq12 {
    a.pow(n.to_u64_digits())
}
fn inv(a: &BigUint, p: &BigUint) -> BigUint {
    let mut x = BigInt::from(a.clone());
    let mut y = BigInt::from(p.clone());
    let mut u = BigInt::from(1);
    let mut v = BigInt::from(0);
    while !y.is_zero() {
        let q = &x / &y;
        (x, y) = (y.clone(), x - &q * &y);
        (u, v) = (v.clone(), u - q * v);
    }
    assert!(x.is_one());
    let modulus = BigInt::from(p.clone());
    let r = ((u % &modulus) + &modulus) % modulus;
    assert_ne!(r.sign(), Sign::Minus);
    r.to_biguint().unwrap()
}
struct Exponents {
    third: BigUint,
    inv_r: BigUint,
    inv_factor: BigUint,
    cube: BigUint,
    lambda: BigUint,
}
static EXP: OnceLock<Exponents> = OnceLock::new();
fn exponents() -> &'static Exponents {
    EXP.get_or_init(|| {
        let q = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
        let r = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();
        let order = q.pow(12) - 1u32;
        let h = &order / &r;
        let lambda = BigUint::from(4965661367192848881u64) * 6u32 + 2u32 + &q + q.pow(3) - q.pow(2);
        let factor = &lambda / &r;
        let mut s = order.clone();
        while (&s % 3u32).is_zero() {
            s /= 3u32;
        }
        Exponents {
            third: &order / 3u32,
            inv_r: inv(&r, &h),
            inv_factor: inv(&(factor / 3u32), &h),
            cube: (s + 1u32) / 3u32,
            lambda,
        }
    })
}
fn decode(bytes: &[u8]) -> Fq12 {
    assert_eq!(bytes.len(), 384);
    let q = Fq::MODULUS.to_bytes_be();
    let vals: Vec<Fq> = bytes
        .chunks_exact(32)
        .map(|b| {
            assert!(b < q.as_slice(), "noncanonical Fq");
            Fq::from_be_bytes_mod_order(b)
        })
        .collect();
    let a = |i| Fq2::new(vals[i], vals[i + 1]);
    Fq12::new(Fq6::new(a(0), a(2), a(4)), Fq6::new(a(6), a(8), a(10)))
}
fn encode(v: Fq12, out: &mut Vec<u8>) {
    for f in [
        v.c0.c0.c0, v.c0.c0.c1, v.c0.c1.c0, v.c0.c1.c1, v.c0.c2.c0, v.c0.c2.c1, v.c1.c0.c0,
        v.c1.c0.c1, v.c1.c1.c0, v.c1.c1.c1, v.c1.c2.c0, v.c1.c2.c1,
    ] {
        let bytes = f.into_bigint().to_bytes_be();
        out.extend(std::iter::repeat(0).take(32 - bytes.len()));
        out.extend(bytes);
    }
}
pub fn prepare() {
    let _ = exponents();
}
pub fn residue_bytes(input: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), 768);
    let value = decode(&input[..384]);
    let root = decode(&input[384..]);
    let e = exponents();
    assert_eq!(pow(root, &27u32.into()), Fq12::one());
    assert_ne!(pow(root, &9u32.into()), Fq12::one());
    assert!(
        Bn254::final_exponentiation(MillerLoopOutput(value))
            .unwrap()
            .0
            .is_one(),
        "invalid pairing"
    );
    let w = (0..3u32)
        .map(|s| pow(root, &s.into()))
        .find(|w| pow(value * w, &e.third).is_one())
        .unwrap();
    let u = pow(pow(value * w, &e.inv_r), &e.inv_factor);
    let mut c = pow(u, &e.cube);
    let correction = pow(root, &e.cube);
    let ui = u.inverse().unwrap();
    let mut iterations = 0;
    while !(c.square() * c * ui).is_one() {
        c *= correction;
        iterations += 1;
        assert!(iterations <= 27);
    }
    assert_eq!(pow(c, &e.lambda), value * w);
    assert!(w.c1.is_zero());
    let mut out = Vec::with_capacity(1152);
    encode(c, &mut out);
    encode(c.inverse().unwrap(), &mut out);
    encode(w, &mut out);
    out
}

/// Versioned fixed-buffer ABI. The caller owns this instance and must discard it
/// after a trap. The kernel produces untrusted witnesses, not a verification proof.
pub mod full;
mod schema;
#[no_mangle]
pub extern "C" fn schema_mask() -> u32 {
    63
}
const MAX_INPUT: usize = 968;
const MAX_OUTPUT: usize = 32488;
static mut INPUT: [u8; MAX_INPUT] = [0; MAX_INPUT];
static mut OUTPUT: [u8; MAX_OUTPUT] = [0; MAX_OUTPUT];
#[no_mangle]
pub extern "C" fn abi_version() -> u32 {
    1
}
#[no_mangle]
pub extern "C" fn input_ptr() -> *mut u8 {
    std::ptr::addr_of_mut!(INPUT).cast()
}
#[no_mangle]
pub extern "C" fn output_ptr() -> *const u8 {
    std::ptr::addr_of!(OUTPUT).cast()
}
#[no_mangle]
pub extern "C" fn prepare_kernel() {
    full::prepare();
}
/// Header: G16H, version 1, schema (1/2 global66 runtime/fixed, 3/4 global67 runtime/fixed, 5 fixed68, 6 runtime68), two zero bytes.
pub fn generate(request: &[u8]) -> Vec<u8> {
    assert!(request.len() >= 8, "short request");
    assert_eq!(&request[..4], b"G16H", "magic");
    assert_eq!(request[4], 1, "version");
    assert_eq!(&request[6..8], &[0, 0], "reserved bytes");
    let schema = schema::get(request[5]);
    assert_eq!(request.len(), 8 + schema.input_bytes, "request length");
    let mut result = request[..8].to_vec();
    result.extend(full::generate(&request[8..], schema));
    result
}
#[no_mangle]
pub extern "C" fn run_kernel(input_len: usize) -> usize {
    assert!(input_len <= MAX_INPUT, "request capacity");
    let input = unsafe { std::slice::from_raw_parts(input_ptr(), input_len) };
    let out = generate(input);
    assert!(out.len() <= MAX_OUTPUT);
    unsafe {
        std::ptr::copy_nonoverlapping(
            out.as_ptr(),
            std::ptr::addr_of_mut!(OUTPUT).cast(),
            out.len(),
        )
    };
    out.len()
}
