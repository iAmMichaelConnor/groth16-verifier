//! Canonical runtime Groth16 key encoding and application statement binding.
//!
//! These functions commit to data; they do NOT check curve membership, a trusted
//! setup, or a Groth16 proof. Complete verifier entry points supply those checks.
//! Expected key hashes must come from application constants or authenticated
//! storage, never solely from the prover's arguments.
use fields::fp::fp_from_limbs_checked;
use poseidon::poseidon2::Poseidon2;

// "G16_RUNTIME_V1": reserved consecutive tags encode different statement types.
pub global DOMAIN: Field = 0x4731365f52554e54494d455f563100;

/// Standard, non-negated key points. G2 order is x.real, x.imag, y.real, y.imag.
/// Each Fq coordinate uses little-endian radix-2^120 limbs (120,120,14 bits).
/// Zero coordinates can encode infinity; point policy belongs to the verifier.
pub struct RawVerificationKey<let N: u32> {
    pub alpha: [[u128; 3]; 2],
    pub beta: [[u128; 3]; 4],
    pub gamma: [[u128; 3]; 4],
    pub delta: [[u128; 3]; 4],
    pub ic: [[[u128; 3]; 2]; N + 1],
}

pub fn key_coordinates<let N: u32>(key: RawVerificationKey<N>) -> [[u128; 3]; 16 + 2 * N] {
    let mut out = [[0; 3]; 16 + 2 * N];
    for i in 0..2 {
        out[i] = key.alpha[i];
    }
    for i in 0..4 {
        out[2 + i] = key.beta[i];
        out[6 + i] = key.gamma[i];
        out[10 + i] = key.delta[i];
    }
    for i in 0..N + 1 {
        out[14 + 2 * i] = key.ic[i][0];
        out[15 + 2 * i] = key.ic[i][1];
    }
    out
}

/// Injective serialization before hashing: every coordinate is strictly below
/// BN254 Fq. Packing then uses 240-bit low words and at most 252-bit high words,
/// both below Noir Fr. N and the domain separate counts and statement purposes.
pub fn key_commitment<let N: u32>(key: RawVerificationKey<N>) -> Field {
    let coordinates = key_coordinates(key);
    for i in 0..16 + 2 * N {
        let _checked = fp_from_limbs_checked(coordinates[i]);
    }
    let packed = packing::pack_bounded(coordinates);
    let mut message = [0; 2 + 16 + 2 * N + (16 + 2 * N + 17) / 18];
    message[0] = DOMAIN;
    message[1] = N as Field;
    for i in 0..16 + 2 * N + (16 + 2 * N + 17) / 18 {
        message[2 + i] = packed[i];
    }
    Poseidon2::hash(message, message.len())
}

pub fn input_commitment<let N: u32>(inputs: [Field; N]) -> Field {
    let mut message = [0; N + 2];
    message[0] = DOMAIN + 1;
    message[1] = N as Field;
    for i in 0..N {
        message[2 + i] = inputs[i];
    }
    Poseidon2::hash(message, N + 2)
}

pub fn pairing_context<let N: u32>(key: RawVerificationKey<N>, inputs: [Field; N]) -> [Field; 3] {
    [N as Field, key_commitment(key), input_commitment(inputs)]
}

pub fn assert_authorized_key<let N: u32>(
    key: RawVerificationKey<N>,
    expected_hash: Field,
) -> Field {
    let actual = key_commitment(key);
    assert(actual == expected_hash, "Unauthorized Groth16 verification key");
    actual
}

/// application = [chain_id, version, consumer_address, action, beneficiary, nonce].
/// The complete offchain verifier returns this digest as its public statement.
/// The consumer reconstructs it from its own context and approved key hash.
/// Binding a nonce does not consume it: replay prevention is application logic.
pub fn statement_id<let N: u32>(
    application: [Field; 6],
    key_hash: Field,
    inputs: [Field; N],
) -> Field {
    let mut message = [0; N + 9];
    message[0] = DOMAIN + 2;
    message[1] = N as Field;
    message[2] = key_hash;
    for i in 0..6 {
        message[3 + i] = application[i];
    }
    for i in 0..N {
        message[9 + i] = inputs[i];
    }
    Poseidon2::hash(message, N + 9)
}

mod tests;
