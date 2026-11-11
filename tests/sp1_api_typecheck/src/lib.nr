// Typecheck-only complete API instantiations; not measured pairing artifacts.
// They use only the public groth16 API, as an external application would.
mod test_keys;
use test_keys::key1::Key1;
pub fn verify_1(
    inputs: [Field; 1],
    components: [[Field; 2]; 1],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    acc: [[[u128; 3]; 12]; 66],
    q: [[u128; 3]; 76],
    res: [[u128; 3]; 9],
) {
    groth16::verify::<Key1, 1>(inputs, raw, residue, components, acc, q, res);
}
use sp1::Sp1Key as Key2;
pub fn verify_2(
    inputs: [Field; 2],
    components: [[Field; 2]; 2],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    acc: [[[u128; 3]; 12]; 66],
    q: [[u128; 3]; 76],
    res: [[u128; 3]; 9],
) {
    groth16::verify::<Key2, 2>(inputs, raw, residue, components, acc, q, res);
}
pub fn verify_sp1_v6(
    program_vkey: Field,
    public_values: [u8; 32],
    proof_nonce: Field,
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 5],
    acc: [[[u128; 3]; 12]; 66],
    q: [[u128; 3]; 76],
    res: [[u128; 3]; 9],
) {
    sp1::v6::verify(
        program_vkey,
        public_values,
        proof_nonce,
        raw,
        residue,
        components,
        acc,
        q,
        res,
    );
}
pub fn sp1_v6_public_inputs(
    program_vkey: Field,
    public_values: [u8; 32],
    nonce: Field,
) -> ([Field; 5], Field) {
    (sp1::v6::public_inputs(program_vkey, public_values, nonce), sp1::v6::VK_ROOT)
}
use test_keys::key3::Key3;
pub fn verify_3(
    inputs: [Field; 3],
    components: [[Field; 2]; 3],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    acc: [[[u128; 3]; 12]; 66],
    q: [[u128; 3]; 76],
    res: [[u128; 3]; 9],
) {
    groth16::verify::<Key3, 3>(inputs, raw, residue, components, acc, q, res);
}

use test_keys::n0::TestKey as Key0;
pub fn verify_0(
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    acc: [[[u128; 3]; 12]; 66],
    q: [[u128; 3]; 76],
    res: [[u128; 3]; 9],
) {
    groth16::verify::<Key0, 0>([], raw, residue, [], acc, q, res);
}
