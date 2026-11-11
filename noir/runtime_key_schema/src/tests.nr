use super::{
    assert_authorized_key, input_commitment, key_commitment, RawVerificationKey, statement_id,
};

// Encoding fixtures, deliberately not valid curve keys. Key validity belongs to
// the complete verifier; these tests isolate commitment and authorization rules.
fn sample<let N: u32>() -> RawVerificationKey<N> {
    RawVerificationKey {
        alpha: [[1, 0, 0], [2, 0, 0]],
        beta: [[3, 0, 0]; 4],
        gamma: [[4, 0, 0]; 4],
        delta: [[5, 0, 0]; 4],
        ic: [[[6, 0, 0], [7, 0, 0]]; N + 1],
    }
}

#[test]
fn binds_key_sections_and_input_count() {
    let key = sample::<1>();
    let expected = key_commitment(key);
    assert(assert_authorized_key(key, expected) == expected);
    let mut changed = key;
    changed.alpha[0][0] += 1;
    assert(key_commitment(changed) != expected);
    changed = key;
    changed.beta[0][0] += 1;
    assert(key_commitment(changed) != expected);
    changed = key;
    changed.gamma[1][0] += 1;
    assert(key_commitment(changed) != expected);
    changed = key;
    changed.delta[2][0] += 1;
    assert(key_commitment(changed) != expected);
    changed = key;
    changed.ic[1][1][0] += 1;
    assert(key_commitment(changed) != expected);
    assert(key_commitment(sample::<0>()) != expected);
    assert(key_commitment(sample::<2>()) != expected);
}

#[test(should_fail_with = "Unauthorized Groth16 verification key")]
fn rejects_changed_key() {
    let key = sample::<1>();
    let expected = key_commitment(key);
    let mut changed = key;
    changed.ic[0][0][0] += 1;
    let _ = assert_authorized_key(changed, expected);
}

#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn rejects_coordinate_equal_to_modulus() {
    let mut key = sample::<1>();
    // q in the same limb encoding; q must not alias the coordinate zero.
    key.alpha[0] = [0x816a916871ca8d3c208c16d87cfd47, 0x4e72e131a029b85045b68181585d97, 0x3064];
    let _ = key_commitment(key);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_compensated_limb_alias() {
    let mut key = sample::<1>();
    key.alpha[0] = [0x1000000000000000000000000000000, 0, 0];
    let _ = key_commitment(key);
}

#[test]
fn binds_statement_key_inputs_and_application() {
    let app: [Field; 6] = [1, 2, 3, 4, 5, 6];
    let inputs: [Field; 2] = [7, -1];
    let expected = statement_id(app, 8, inputs);
    assert(statement_id(app, 9, inputs) != expected);
    for i in 0..6 {
        let mut changed = app;
        changed[i] += 1;
        assert(statement_id(changed, 8, inputs) != expected);
    }
    for i in 0..2 {
        let mut changed = inputs;
        changed[i] += 1;
        assert(statement_id(app, 8, changed) != expected);
    }
    assert(input_commitment([7]) != input_commitment([7, 0]));
}
