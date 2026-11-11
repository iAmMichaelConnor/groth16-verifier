//! SP1 public-input mapping: program key and SHA256 public-values digest masked to 253 bits.
use sha256::sha256_var;

/// Convert 32 big-endian bytes to a Field element.
fn bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Convert a SHA256 hash to a BN254 scalar by masking to 253 bits.
/// Clears the top 3 bits so the value fits in the scalar field.
pub fn hash_to_field(hash: [u8; 32]) -> Field {
    let mut masked = hash;
    masked[0] = masked[0] & 0x1F;
    bytes32_to_field(masked)
}

/// Hash public values using SHA256 and mask to 253 bits.
fn hash_public_values<let N: u32>(public_values: [u8; N]) -> Field {
    let hash: [u8; 32] = sha256_var(public_values, N);
    hash_to_field(hash)
}

/// SP1 public inputs: [vkey, H(public_values)] where H is SHA256.
pub fn sp1_public_inputs<let N: u32>(vkey: Field, public_values: [u8; N]) -> [Field; 2] {
    let input0 = vkey;
    let input1 = hash_public_values(public_values);
    [input0, input1]
}

/// One test per code path (the masking, one hashed public-value array), run
/// constrained nightly; every test runs per pull request in the fast mode.
mod nightly {
    use super::{hash_to_field, sp1_public_inputs};

    #[test]
    fn hash_mapping_masks_only_digest_high_bits() {
        let hash: [u8; 32] = std::hint::black_box([255; 32]);
        assert(
            hash_to_field(hash)
                == 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        );
    }

    #[test]
    fn public_inputs_abc_retain_full_program_key() {
        let vkey: Field = std::hint::black_box(-1);
        let values: [u8; 3] = std::hint::black_box([97, 98, 99]);
        let inputs = sp1_public_inputs(vkey, values);
        assert(inputs[0] == vkey);
        assert(inputs[1] == 0x1a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad);
    }
}

#[test]
fn public_inputs_seventeen_bytes_retain_full_program_key() {
    let vkey: Field = std::hint::black_box(-1);
    let values: [u8; 17] =
        std::hint::black_box([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let inputs = sp1_public_inputs(vkey, values);
    assert(inputs[0] == vkey);
    assert(inputs[1] == 0x1e5718fea51a8f3f5baca61c77afab473c1810f8b9db330273b4011ce92c787e);
}

#[test]
fn public_inputs_thirty_two_bytes_retain_full_program_key() {
    let vkey: Field = std::hint::black_box(-1);
    let values: [u8; 32] = std::hint::black_box([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]);
    let inputs = sp1_public_inputs(vkey, values);
    assert(inputs[0] == vkey);
    assert(inputs[1] == 0x030dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd);
}
