use poseidon::poseidon2::Poseidon2;

// Caller precondition: every limb has already been range checked to 120/120/14.
// Packing combines the two low limbs into <2^240 and groups 18 high limbs into
// <2^252, both below Fr. Fixed arity, order and padding make this injective on
// bounded encodings. Internal Fq representatives differing by q have different
// encoded transcripts; modular equality does not make their encodings identical.
// Encoding length is N+ceil(N/18), plus the fixed header. Low words
// a0+2^120*a1 are <2^240 and high groups sum_j a2_j*2^(14*j)
// are <2^252<r. The caller's limb bounds are necessary for injectivity.
// Do not hash an unchecked encoding and subsequently reduce it modulo q:
// the polynomial challenge must bind the actual bounded witness representation.
pub fn transcript_hash<let N: u32, let M: u32>(
    header: [Field; M],
    coeffs: [[u128; 3]; N],
) -> Field {
    let encoded = packing::pack_bounded(coeffs);
    let mut transcript = [0; M + N + (N + 17) / 18];
    for i in 0..M {
        transcript[i] = header[i];
    }
    for i in 0..N + (N + 17) / 18 {
        transcript[M + i] = encoded[i];
    }
    Poseidon2::hash(transcript, M + N + (N + 17) / 18)
}
