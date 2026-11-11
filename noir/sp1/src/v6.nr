//! SP1 v6 Groth16 proofs, SP1 circuit version v6.1.0: the Groth16 key and
//! recursion verification-key root that SP1 v6.1.0 through v6.10.0 use. Proofs
//! from SP1 v6.0.0 to v6.0.2 (circuit version v6.0.0) have another key and root
//! and are rejected, as are SP1 v5 proofs.
//!
//! The SP1 v6 Groth16 wrapper has five public inputs, in this order: the
//! program vkey hash, SHA-256 of the public values with the top three bits
//! cleared, the exit code, the recursion verification-key root and the proof
//! nonce. [`verify`] binds all five as SP1's onchain verifier does: the exit
//! code is zero and the root is [`VK_ROOT`], both fixed in the circuit; the
//! program vkey, public values and nonce are arguments.
//!
//! A valid proof says only that the SP1 program with that vkey ran to exit code
//! zero and committed those public values. The application must authorise the
//! program vkey and interpret the public values. The nonce is chosen by whoever
//! requested the proof; SP1 binds it but gives it no meaning, and neither does
//! this module.
use crate::generated::v6_key::Key5;
use crate::inputs::hash_to_field;
use groth16::provider::{FixedKey, Fp12, Half, LineScheduleRaw, VerifyingKey};
use sha256::sha256_var;

mod binding_tests;

pub use crate::generated::v6_key::VK_ROOT;

/// The only exit code SP1's v6 onchain verifier accepts.
global SUCCESS_EXIT_CODE: Field = 0;

/// The pinned SP1 v6 (circuit version v6.1.0) Groth16 verification key with
/// its trusted preprocessing. Every method delegates to the generated `Key5`,
/// the single source of the key data; scripts/tests/test_sp1_key.py checks
/// that data against the saved SP1 key.
///
/// Crate-private on purpose: `groth16::verify::<Sp1V6Key, 5>` with
/// caller-built inputs would skip the exit-code and root pins (an exit code or
/// root taken from proof bytes accepts failed executions and proofs for other
/// recursion keys). Applications call [`verify`].
pub(crate) struct Sp1V6Key {}
impl FixedKey<5> for Sp1V6Key {
    fn verification_key() -> VerifyingKey<6> {
        Key5::verification_key()
    }
    fn msm_points() -> [Half; 20] {
        Key5::msm_points()
    }
    fn msm_correction() -> Half {
        Key5::msm_correction()
    }
    fn msm_correction_including_offset() -> Half {
        Key5::msm_correction_including_offset()
    }
    fn msm_offset_pairs() -> [[Field; 5]; 681] {
        Key5::msm_offset_pairs()
    }
    fn gamma_lines() -> LineScheduleRaw {
        Key5::gamma_lines()
    }
    fn delta_lines() -> LineScheduleRaw {
        Key5::delta_lines()
    }
    fn t_preimage() -> Fp12 {
        Key5::t_preimage()
    }
}

/// The five Groth16 public inputs of an SP1 v6 proof that verifies onchain:
/// [program vkey, SHA-256(public values) masked to 253 bits, exit code 0,
/// VK_ROOT, proof nonce].
pub fn public_inputs<let N: u32>(
    program_vkey: Field,
    public_values: [u8; N],
    proof_nonce: Field,
) -> [Field; 5] {
    let digest = hash_to_field(sha256_var(public_values, N));
    [program_vkey, digest, SUCCESS_EXIT_CODE, VK_ROOT, proof_nonce]
}

/// Verify an SP1 v6 Groth16 proof of `public_values` for the program
/// `program_vkey`, with the proof's `proof_nonce`. `raw` holds A, B, C and the
/// input point L as 120/120/14-bit Fq limbs; the other arguments are hints.
/// The groth16-verifier-sp1 host package parses SP1 proof bytes and prepares
/// all of them.
pub fn verify<let N: u32>(
    program_vkey: Field,
    public_values: [u8; N],
    proof_nonce: Field,
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 5],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) {
    groth16::verify::<Sp1V6Key, 5>(
        public_inputs(program_vkey, public_values, proof_nonce),
        raw,
        residue,
        components,
        accumulators,
        quotient,
        block_residuals,
    );
}

/// The input layout and the hash of empty public values, run constrained
/// nightly; the binding tests in `binding_tests` run in the fast mode only.
mod nightly {
    use super::public_inputs;

    #[test]
    fn public_inputs_follow_the_sp1_v6_layout() {
        let vkey: Field = std::hint::black_box(-1);
        let nonce: Field = std::hint::black_box(7);
        let values: [u8; 3] = std::hint::black_box([97, 98, 99]);
        let inputs = public_inputs(vkey, values, nonce);
        assert(inputs[0] == vkey);
        assert(inputs[1] == 0x1a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad);
        assert(inputs[2] == 0);
        assert(inputs[3] == 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352);
        assert(inputs[4] == nonce);
    }

    #[test]
    fn public_inputs_hash_empty_public_values() {
        let values: [u8; 0] = std::hint::black_box([]);
        let inputs = public_inputs(1, values, 0);
        // SHA-256 of the empty string, top three bits cleared.
        assert(inputs[1] == 0x03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855);
    }
}
