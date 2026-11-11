#!/usr/bin/env bash
# The verifier packages export only complete entry points. Helpers that check
# part of a Groth16 statement (the pairing relation without the public-input
# binding, the input validators, the G1 MSM without the pairing check) must not
# be reachable from another package: a pairing-product check without the
# binding is forgeable. The SP1 v6 key is private too: with caller-built
# inputs it would skip the exit-code and root pins that `sp1::v6::verify`
# applies. This compiles small consumer packages with `nargo check`: the public
# API must resolve and every listed item must not.
set -eu

NARGO=${NARGO:-nargo}
root="$(cd "$(dirname "$0")/.." && pwd)"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

check() { # check <name> <lib.nr source>; prints nargo's output, returns its status
    mkdir -p "$scratch/$1/src"
    cat > "$scratch/$1/Nargo.toml" <<EOF
[package]
name = "$1"
type = "lib"
authors = [""]

[dependencies]
groth16 = { path = "$root/noir/groth16" }
runtime_verifier = { path = "$root/noir/runtime_verifier" }
bn254_pairing = { path = "$root/noir/bn254_pairing" }
sp1 = { path = "$root/noir/sp1" }
EOF
    cp "$root/tests/fixed_multiplier_vector/src/key1.nr" "$scratch/$1/src/key1.nr"
    printf '%s\n' "$2" > "$scratch/$1/src/lib.nr"
    (cd "$scratch/$1" && "$NARGO" check 2>&1 >/dev/null)
}

public='mod key1;
use key1::Key1;
use groth16::{FixedKey, verify};
use groth16::provider::{VerifyingKey, Half, Fp, Fp2, Fp6, Fp12, G1Affine, G2Affine, LineEvaluation, LineScheduleRaw, BigNum, Proof};
use runtime_verifier::{Hints, RawVerificationKey, key_commitment, assert_authorized_key, statement_id};
use bn254_pairing::{pairing, pairing_multi, miller_loop, final_exponentiation};
use bn254_pairing::g2::{is_in_correct_subgroup_g2, is_in_correct_subgroup_g2_fast};
use sp1::{Sp1Key, sp1_public_inputs, hash_to_field};
use sp1::v6::{public_inputs, VK_ROOT};
pub fn fixed(inputs: [Field; 1], raw: [[u128; 3]; 10], residue: [[u128; 3]; 36], components: [[Field; 2]; 1], acc: [[[u128; 3]; 12]; 66], q: [[u128; 3]; 76], res: [[u128; 3]; 9]) {
    verify::<Key1, 1>(inputs, raw, residue, components, acc, q, res);
}
pub fn runtime(key: RawVerificationKey<1>, inputs: [Field; 1], proof: [[u128; 3]; 8], hints: Hints<1>) -> Field {
    runtime_verifier::verify(key, inputs, proof, hints)
}
pub fn sp1_v5(vkey: Field, values: [u8; 4], raw: [[u128; 3]; 10], residue: [[u128; 3]; 36], components: [[Field; 2]; 2], acc: [[[u128; 3]; 12]; 66], q: [[u128; 3]; 76], res: [[u128; 3]; 9]) -> Field {
    verify::<Sp1Key, 2>(sp1_public_inputs(vkey, values), raw, residue, components, acc, q, res);
    hash_to_field([0; 32])
}
pub fn sp1_v6(vkey: Field, values: [u8; 4], nonce: Field, raw: [[u128; 3]; 10], residue: [[u128; 3]; 36], components: [[Field; 2]; 5], acc: [[[u128; 3]; 12]; 66], q: [[u128; 3]; 76], res: [[u128; 3]; 9]) -> ([Field; 5], Field) {
    sp1::v6::verify(vkey, values, nonce, raw, residue, components, acc, q, res);
    (public_inputs(vkey, values, nonce), VK_ROOT)
}'
if ! output=$(check public "$public"); then
    echo "the public API failed to resolve:" >&2
    echo "$output" >&2
    exit 1
fi

forbidden=(
    groth16::optimized::global_pairing::verify_fixed
    groth16::optimized::fixed_verifier::verify
    groth16::optimized::entry::validate_private_fixed_inputs
    groth16::optimized::entry::decode_finite_proof_and_validate_b
    groth16::optimized::fixed_key_glv::glv_fixed
    runtime_verifier::checked_pairing
    runtime_verifier::checked_g1_private
    runtime_verifier::assemble
    sp1::v6::Sp1V6Key
    sp1::generated::v6_key::Key5
)
for path in "${forbidden[@]}"; do
    name=$(echo "$path" | tr ':' '_')
    if output=$(check "$name" "use $path as forbidden;"); then
        echo "$path is reachable from another package" >&2
        exit 1
    fi
    if ! grep -qE "private|Could not resolve" <<< "$output"; then
        echo "$path: rejected for a reason other than visibility:" >&2
        echo "$output" >&2
        exit 1
    fi
done
echo "public API: ok"
