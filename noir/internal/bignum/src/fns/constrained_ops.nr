use crate::constants::{GRUMPKIN_MODULUS, TWO_POW_120, TWO_POW_240};

use crate::fns::{
    expressions::{evaluate_quadratic_expression, validate_udiv_mod_expression},
    unconstrained_helpers::{
        __from_field, compute_add_flags, compute_borrow_flags, compute_gte_flags, compute_sub_flags,
    },
    unconstrained_ops::{__add, __div, __mul, __neg, __sqr, __sub, __udiv_mod},
};

use crate::params::BigNumParams;

use std::cmp::Ordering;

/// Lift the limbs of a `BigNum` value onto the circuit `Field`
///
/// Descent the `BigNum` value back into the `Field` and
///    - check that it's a proper `BigNum` value
///    - validate the limbs sum up to a `Field` value
pub(crate) fn limbs_to_field<let N: u32, let MOD_BITS: u32>(
    _params: &BigNumParams<N, MOD_BITS>,
    limbs: &[u128; N],
) -> Field {
    validate_in_range::<N, MOD_BITS>(limbs);
    // `validate_in_range` bounds `limbs` by `2^MOD_BITS`, so when `MOD_BITS < 254` the value is
    // already known to be smaller than the Grumpkin modulus: the latter's top limb is `0x3064`,
    // hence `GRUMPKIN_MODULUS > 0x3064 * 2^240 > 2^253`. Only `MOD_BITS >= 254` needs the
    // explicit comparison below.
    //
    // The comparison must be *skipped* rather than left in as a redundant check: `validate_gt`
    // range-constrains the top limb of `GRUMPKIN_MODULUS - limbs` to `MOD_BITS - (N - 1) * 120`
    // bits, which for e.g. `MOD_BITS = 253, N = 3` is 13 bits — too tight to hold the Grumpkin
    // modulus' own 14-bit top limb, so every value would fail the range check.
    if (N > 2) & (MOD_BITS >= 254) {
        // validate that the `BigNum` is less than the Grumpkin modulus
        let mut grumpkin_modulus: [u128; N] = [0; N];
        grumpkin_modulus[0] = GRUMPKIN_MODULUS[0];
        grumpkin_modulus[1] = GRUMPKIN_MODULUS[1];
        grumpkin_modulus[2] = GRUMPKIN_MODULUS[2];
        validate_gt::<N, MOD_BITS>(&grumpkin_modulus, limbs);
    }

    if N < 2 {
        limbs[0] as Field
    } else if N == 2 {
        (limbs[0] as Field) + (limbs[1] as Field) * (TWO_POW_120 as Field)
    } else {
        (limbs[0] as Field)
            + (limbs[1] as Field) * (TWO_POW_120 as Field)
            + (limbs[2] as Field) * TWO_POW_240
    }
}

/// Construct a `BigNum` value from a native `Field`
///
/// Decomposes the `Field` value into 120-bit limbs
/// then we have three cases:
///     - MOD_BITS < 254 (grumpkin_mod_bits): it is enough to call for `validate_in_field`, which is basically `val < MOD`
///     - MOD_BITS > 254: we need to verify that the obtained `BigNum` `val < GRUMPKIN_MODULUS`
///     - MOD_BITS = 254: verify that `val < min(MOD, GRUMPKIN_MODULUS)`
/// Next we verify that all the limbs are properly ranged
/// and that the accumulated limbs are equal to the input `Field` value
pub fn from_field<let N: u32, let MOD_BITS: u32>(
    _params: &BigNumParams<N, MOD_BITS>,
    val: Field,
) -> [u128; N] {
    // Safety: we check that the resulting limbs represent the intended field element
    // we check the bit length, the limbs being max 120 bits, and the value in total is less than the field modulus
    let result: [u128; N] = unsafe { __from_field::<N>(val) };

    if !std::runtime::is_unconstrained() {
        // validate the limbs are in range and the value in total is less than 2^254
        if MOD_BITS < 254 {
            // this means that the field modulus is smaller than grumpkin modulus so we have to check if the element fields in the field size
            validate_in_field(_params, &result);
        } else {
            let mut grumpkin_modulus: [u128; N] = [0; N];
            grumpkin_modulus[0] = GRUMPKIN_MODULUS[0];
            grumpkin_modulus[1] = GRUMPKIN_MODULUS[1];
            grumpkin_modulus[2] = GRUMPKIN_MODULUS[2];

            if MOD_BITS > 254 {
                // this means that the field modulus is larger than grumpkin modulus so we have to check if the element fields in the field size are less than the grumpkin modulus.
                // also for correct params N is always larger than 3 here
                validate_gt::<N, MOD_BITS>(&grumpkin_modulus, &result);
            } else {
                // this is the tricky part, when MOD_BITS = 254, we have to compare the limbs of the modulus to the grumpkin modulus limbs
                // any `BigNum` with 254 bits will have 3 limbs

                // if MOD is less than grumpkin modulus, this will be true
                let mut mod_lt_grumpkin: bool = false;
                let mut decided: bool = false;
                for i in 0..3 {
                    if !decided & (_params.modulus[2 - i] != grumpkin_modulus[2 - i]) {
                        mod_lt_grumpkin = _params.modulus[2 - i] < grumpkin_modulus[2 - i];
                        decided = true;
                    }
                }

                let min_modulus: [u128; N] = if mod_lt_grumpkin {
                    _params.modulus
                } else {
                    grumpkin_modulus
                };
                validate_gt::<N, MOD_BITS>(&min_modulus, &result);
            }
        }
        validate_in_range::<N, MOD_BITS>(&result);

        // validate the limbs sum up to the field value
        let field_val: Field = if N < 2 {
            result[0] as Field
        } else if N == 2 {
            (result[0] as Field) + (result[1] as Field) * (TWO_POW_120 as Field)
        } else {
            (result[0] as Field)
                + (result[1] as Field) * (TWO_POW_120 as Field)
                + (result[2] as Field) * TWO_POW_240
        };
        assert_eq(field_val, val);
    }

    result
}

/// Given an input seed, generate a pseudorandom `BigNum` value
///
/// This function *should* produce a uniformly randomly distributed value modulo `MOD`
///
///  First we take the seed and pack it's 31-byte chunks into `Field`s
///  A length separator (SeedBytes) is appended to the seed before hashing
///  to prevent collisions between seeds that differ only in leading zeros.
///
///  We use a hash function that can be modelled as a random oracle
///  We hash the packed seed using Poseidon2 to produce `MOD_BITS * 2` bits of entropy
///
///  From these bits we construct 4(in case N = 2) or 3(N > 2) `BigNum` values:
///  - We fill first `N - 1` limbs and leave the top limb empty
///
///  Then we accumulate the resulting BigNum values using:
///  B = 2^{120 * (N - 1)}
///  res = x3 + B * x2 + B^2 * x1 + B^3 * x0
///
/// ## Note
/// This function will always produce an `x3` `BigNum`
/// If `MOD = 2^{120 * (N - 1)}`
/// It will use only `MOD_BITS - 1` bits of entropy
pub fn derive_from_seed<let N: u32, let MOD_BITS: u32, let SeedBytes: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    seed: [u8; SeedBytes],
) -> [u128; N] {
    // Pack seed bytes into Fields.
    // For the seed of length M, we construct a rolling_hash_field of size ceil(M / 31).
    // i.e.  31 bytes per Field
    // NOTE: the Fields produced are 248 bits in size

    assert(SeedBytes < 256, "derive_from_seed: seed is too big");
    let mut rolling_hash_fields: [Field; (SeedBytes + 31) / 31] = [0; (SeedBytes + 31) / 31];
    let mut seed_ptr: u32 = 0;
    for i in 0..(SeedBytes + 31) / 31 {
        let mut packed: Field = 0;
        for _ in 0..31 {
            if (seed_ptr < SeedBytes) {
                packed *= 256;
                packed += seed[seed_ptr] as Field;
                seed_ptr += 1;
            } else if seed_ptr == SeedBytes {
                packed *= 256;
                packed += SeedBytes as Field;
                seed_ptr += 1;
            }
        }
        rolling_hash_fields[i] = packed;
    }

    let compressed: Field =
        poseidon::poseidon2::Poseidon2::hash(rolling_hash_fields, (SeedBytes + 31) / 31);
    let mut rolling_hash: [Field; 2] = [compressed, 0];

    // 120 bit limb has 15 bytes in it
    // we buffer (N * 15) * 2 bytes for 2N limbs
    let mut hash_buffer: [u8; N * 15 * 2] = [0; N * 15 * 2];

    // We produce 32 bytes (254 bits) per hash iteration
    // We take only 30 bytes, so we need ceil(N * 2 * 15 / 30) hashes to fill them up
    for i in 0..N {
        let hash: Field = poseidon::poseidon2::Poseidon2::hash(rolling_hash, 2);
        let hash: [u8; 32] = hash.to_le_bytes();
        for j in 0..30 {
            hash_buffer[i * 30 + j] = hash[j];
        }
        rolling_hash[1] += 1;
    }

    let num_bits: u32 = MOD_BITS * 2;
    let num_bytes: u32 = (num_bits + 7) / 8;

    // Truncate the final byte that will be used in `BigNum` creation
    let bits_in_last_byte: u8 = (num_bits as u8) % 8;
    if bits_in_last_byte != 0 {
        let last_byte_mask: u8 = ((1 as u8) << bits_in_last_byte) - 1;
        hash_buffer[num_bytes - 1] &= last_byte_mask;
    }

    let num_bigfield_chunks: u32 = if N == 2 { 4 } else { 3 };
    let mut byte_ptr: u32 = 0;

    // We want to convert our hash_buffer into bigfield chunks, with each `BigNum` having at most N - 1 limbs filled
    // We sample only N - 1 limbs mostly because we do not wont to deal with accidental overflows in the top limb
    // In any case the security is preserved
    //
    // For all integer values N > 1, the number of chunks is either 4(for N = 2) or 3(for N > 2) (ceil(2*N / (N - 1)))
    //
    // To determine the exact number of chunks, we need the `!=` or `>` operator which is not available when defining array sizes
    // so we overestimate at 4
    // e.g. if N = 20, then we have 40 limbs we want to reduce, but each bigfield chunk is 19 limbs, so we need 3
    // if N = 2, we have 4 limbs we want to reduce but each bigfield chunk is only 1 limb, so we need 4
    let mut bigfield_chunks: [[u128; N]; 4] = [[0; N]; 4];

    for k in 0..num_bigfield_chunks {
        let mut bigfield_limbs: [u128; N] = [0; N];

        // Before the current limb, we filled out (N - 1) limbs, k times
        // 15 bytes per limb
        // resulting in total of 15 * k * (N - 1)
        let num_filled_bytes: u32 = 15 * k * (N - 1);
        if num_bytes > num_filled_bytes {
            // Static assert for completeness
            assert(num_filled_bytes == byte_ptr);

            let num_remaining_bytes_to_sample: u32 = num_bytes - num_filled_bytes;
            let num_remaining_limbs_to_sample: u32 = (num_remaining_bytes_to_sample + 14) / 15;

            // Sample at most (N - 1) limbs from hash_buffer
            let num_limbs_to_sample: u32 = if num_remaining_limbs_to_sample > (N - 1) {
                N - 1
            } else {
                num_remaining_limbs_to_sample
            };

            for j in 0..num_limbs_to_sample {
                let mut limb: Field = 0;
                // Construct a 120 bit limb
                for _ in 0..15 {
                    if byte_ptr < num_bytes {
                        let byte: u8 = hash_buffer[byte_ptr];
                        limb *= 256;
                        limb += byte as Field;
                        byte_ptr += 1;
                    }
                }
                // crucial for performance
                limb.assert_max_bit_size::<120>();
                // Accumulate limbs from top to bottom
                bigfield_limbs[num_limbs_to_sample - 1 - j] = limb as u128;
            }
            // Accumulate `BigNum` values from top to bottom
            bigfield_chunks[num_bigfield_chunks - 1 - k] = bigfield_limbs;
        }
    }

    // B = 2^{120 * (N - 1)}, we know it is \leq `MOD`, since the top limb
    // have to be at least one
    let mut bigfield_rhs_limbs: [u128; N] = [0; N];
    bigfield_rhs_limbs[N - 1] = 1;

    let mut result: [u128; N] = bigfield_chunks[0];

    for i in 1..num_bigfield_chunks {
        result = mul(*params, result, bigfield_rhs_limbs);
        result = add(params, &result, &bigfield_chunks[i]);
    }

    result
}

// ------------------------------ COMPARISON FUNCTIONS ------------------------------

/// Validate `lhs != rhs (mod MOD)` for range-bounded representatives.
///
/// Three-limb values retain their exact equality specialization and MOD_BITS
/// operand bounds. Other limb counts accept 120-bit lower limbs and one extra
/// top bit, including canonical-plus-modulus aliases. Their equality helper
/// checks normalized modulus/layout and exact integer offsets through +/-3*MOD.
/// The generic path uses no native-field-only shortcut and no
/// canonical-only subtraction hint.
pub fn assert_is_not_equal<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    lhs: &[u128; N],
    rhs: &[u128; N],
) {
    assert(!eq::<N, MOD_BITS>(params, lhs, rhs), "assert_is_not_equal fail");
}

/// Compute exact modular equality with layout-specific operand bounds.
///
/// N=3 retains the declared MOD_BITS operand envelope and its existing
/// normalized-modulus precondition. Other limb counts validate modulus
/// normalization locally and permit one additional top bit, preserving the
/// canonical-plus-modulus producers. Such operands are below 2^(MOD_BITS+1)
/// <= 4*MOD; their equal-residue differences are 0, +/-MOD, +/-2*MOD, +/-3*MOD.
/// The generic path uses constrained integer carries and no subtraction hint.
// Three-limb derivation: d=low+B^2*high, B=2^120, |low|<B^2.
// Normalization and limb bounds imply each input<2^MOD_BITS<=2*MOD, so
// equal residues have d in {0,+MOD,-MOD}. For +MOD, high-qhigh is 0 or 1;
// for -MOD, high+qhigh is 0 or -1. Their quadratic root checks select exactly
// those integer carries. The remaining residual has |residual|<2^241<Fr,
// making native equality exact. The zero branch additionally fixes high=0.
// Negating this exact flag is the N=3 inequality completeness repair; the
// other-N fallback does not acquire this three-limb argument.
pub fn eq<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    lhs: &[u128; N],
    rhs: &[u128; N],
) -> bool {
    if N == 3 {
        // Keep the documented BigNum range precondition explicit. No canonicality assumption.
        validate_in_range::<N, MOD_BITS>(lhs);
        validate_in_range::<N, MOD_BITS>(rhs);
        let radix = TWO_POW_120 as Field;
        let radix2 = radix * radix;
        let low = (lhs[0] as Field) + radix * (lhs[1] as Field)
            - (rhs[0] as Field)
            - radix * (rhs[1] as Field);
        let high = (lhs[2] as Field) - (rhs[2] as Field);
        let qlow = (params.modulus[0] as Field) + radix * (params.modulus[1] as Field);
        let qhigh = params.modulus[2] as Field;
        // Each input is below 2^MOD_BITS <= 2*MOD. The only possible equal-residue
        // integer differences are 0, +MOD, -MOD. Each low comparison is exact:
        // its magnitude is below 2^241, well below the native field modulus.
        let native_diff = low + radix2 * high;
        let native_modulus = qlow + radix2 * qhigh;
        let positive_carry = high - qhigh;
        let negative_carry = high + qhigh;
        // The carry-root checks limit each residual integer to magnitude <2^241,
        // so equality in the native field is then equality over the integers.
        ((native_diff == 0) & (high == 0))
            | ((native_diff == native_modulus) & (positive_carry * (positive_carry - 1) == 0))
            | ((native_diff == -native_modulus) & (negative_carry * (negative_carry + 1) == 0))
    } else {
        wide_modular_eq::<N, MOD_BITS>(params, lhs, rhs)
    }
}

/// Exact generic comparison envelope: N>=1, 1<=TOP_BITS<=120, normalized
/// modulus with exactly MOD_BITS bits. Check these premises even for public
/// parameter literals. Barrett constants and primality are not used here.
fn wide_modular_eq<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    lhs: &[u128; N],
    rhs: &[u128; N],
) -> bool {
    let supported = (N > 0) & (MOD_BITS > 120 * (N - 1)) & (MOD_BITS <= 120 * N);
    assert(supported, "unsupported comparison geometry");
    if supported {
        validate_in_range::<N, MOD_BITS>(&params.modulus);
        let leading_bit: Field = (1u128 << ((MOD_BITS - 120 * (N - 1) - 1) as u128)) as Field;
        ((params.modulus[N - 1] as Field) - leading_bit)
            .assert_max_bit_size::<MOD_BITS - 120 * (N - 1) - 1>();
        for i in 0..N - 1 {
            (lhs[i] as Field).assert_max_bit_size::<120>();
            (rhs[i] as Field).assert_max_bit_size::<120>();
        }
        (lhs[N - 1] as Field).assert_max_bit_size::<MOD_BITS - 120 * (N - 1) + 1>();
        (rhs[N - 1] as Field).assert_max_bit_size::<MOD_BITS - 120 * (N - 1) + 1>();
        let mut equal = *lhs == *rhs;
        for factor in 1..4 {
            equal = equal
                | equal_modulus_offset(lhs, rhs, &params.modulus, factor as u128)
                | equal_modulus_offset(rhs, lhs, &params.modulus, factor as u128);
        }
        equal
    } else {
        false
    }
}

/// Test large = small + factor*MOD over integers, for factor in 1..=3.
/// Caller enforces low limbs<B=2^120 and top limbs<2^(TOP_BITS+1)<=2B.
/// Low sums are <4B, carry<=3 and the final top sum is <5B<2^123.
/// All arithmetic fits u128 and the native field; no hint chooses carries.
/// Compare the FULL final top sum: masking it would discard a valid carry.
fn equal_modulus_offset<let N: u32>(
    large: &[u128; N],
    small: &[u128; N],
    modulus: &[u128; N],
    factor: u128,
) -> bool {
    let mut carry: u128 = 0;
    let mut equal = true;
    for i in 0..N - 1 {
        let sum = small[i] + factor * modulus[i] + carry;
        equal = equal & (large[i] == (sum & (TWO_POW_120 - 1)));
        carry = sum >> 120;
    }
    let top = small[N - 1] + factor * modulus[N - 1] + carry;
    equal & (large[N - 1] == top)
}

/// Validate that `val` is not equal to zero when interpreted as an integer.
///
/// This enforces that at least one limb of `val` is non-zero.
/// It does *not* check "BigNum zero" in the modular sense (e.g. it
/// treats `MOD` as non-zero).
///
/// ## Assumptions
/// * Each limb of `val` is range-constrained to be a 120-bit value:
///   `0 <= val[i] < 2^120`.
/// * For our concrete fields and limb counts we have `N * 2^120 < p`,
///   so the sum of all limbs fits strictly inside the field modulus.
///
/// ## Completeness
/// If `val` is non-zero as an integer, then at least one limb is non-zero,
/// so the integer sum of the limbs satisfies `0 < limb_sum < p`. In this
/// case `limb_sum != 0` in the `Field`, and the assertion passes.
///
/// ## Soundness
/// If all limbs of `val` are zero, then `limb_sum` is zero as an integer
/// and as a field element, so the assertion fails. A witness representing
/// the zero integer can never satisfy this check.
///
/// ## Note
/// This is slightly cheaper than doing `val != [0; N]`, as we avoid
/// creating per-limb boolean equalities and chaining them with `and`s.
pub fn assert_is_not_zero_integer<let N: u32>(val: &[u128; N]) {
    assert(!is_zero_integer(val), "assert_is_not_zero_integer fail");
}

/// Check whether `val` is the zero `BigNum` in the integer sense.
///
/// This returns `true` iff all limbs of `val` are zero. It does *not*
/// treat `MOD` as zero; for modular `BigNum` zero use `is_zero`.
///
/// See `assert_is_not_zero_integer` for the underlying assumptions.
///
/// ## Note
/// This is slightly cheaper than testing `val == [0; N]`, as we avoid
/// creating per-limb boolean equalities and chaining them with `and`s.
pub fn is_zero_integer<let N: u32>(val: &[u128; N]) -> bool {
    let mut limb_sum: Field = 0;
    for i in 0..N {
        limb_sum += val[i].into();
    }
    limb_sum == 0
}

/// Validate that a `BigNum` value is not zero modulo `MOD`.
///
/// Convenience wrapper around `assert_is_not_equal`.
pub fn assert_is_not_zero<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    val: &[u128; N],
) {
    let zero: [u128; N] = [0; N];
    assert_is_not_equal::<N, MOD_BITS>(params, val, &zero);
}

/// Check whether a `BigNum` value is zero modulo `MOD`.
///
/// This treats both the all-zero limb vector and `params.modulus` as
/// representing zero. It assumes that all valid `BigNum` values are
/// range-constrained so that no other representatives of `0 (mod MOD)`
/// can appear.
///
/// ## Note
/// This is cheaper than calling `eq(val, [0; N])`
pub fn is_zero<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    val: &[u128; N],
) -> bool {
    is_zero_integer(val) | (*val == params.modulus)
}

/// Validate a `BigNum` instance is correctly range constrained to contain no more than `MOD_BITS` bits
///
/// Constrain the `BigNum` instance to be < 2^MOD_BITS by:
///     - Constraining each limb(0..N-2) to be 120-bit limb
///     - Constraining the last limb to be `MOD_BITS - 120 * (N - 1)`
///
/// ## Note
/// This can be a very expensive function, when the `TOP_LIMB_BITS` is uncommon
///
/// For example: BLS12_377Fr, with `TOP_LIMB_BITS`=13
/// It creates a new 13-bit range table, which consists of roughly 3k variables
/// And ~2k circuit gates
///
/// Compare this to BLS12_377Fq, with `TOP_LIMB_BITS`=17
/// It is nicely decomposed into
/// 14-bit range check and 3-bit range check - much much cheaper, since 14-bit range checks
/// are already pretty common for 120-bit range checks
pub fn validate_in_range<let N: u32, let MOD_BITS: u32>(limbs: &[u128; N]) {
    for i in 0..(N - 1) {
        (limbs[i] as Field).assert_max_bit_size::<120>();
    }

    (limbs[N - 1] as Field).assert_max_bit_size::<MOD_BITS - ((N - 1) * 120)>();
}

/// Validate quotient produced from `evaluate_quadratic_expression` is well-formed
///
/// Because the inputs into `evaluate_quadratic_expression` may cause the quotient to extend beyond `Params::modulus_bits`.
///           We allow the quotient to extend `6` bits beyond `Params::modulus_bits()`
///           Why is this?
///           several factors:    1. quotient * modulus , limbs cannot overflow `Field` boundary (254 bits)
///                               2. in `evaluate_quadratic_expression`, we require that for `expression - quotient * modulus`,
///                                  limbs cannot exceed `246` bits (246 magic number due to a higher number adding extra range check gates)
///           because of factor 2 and the fact that modulus limbs are 120 bits, quotient limbs cannot be > 126 bits
pub(crate) fn validate_quotient_in_range<let N: u32, let MOD_BITS: u32>(limbs: &[u128; N]) {
    for i in 0..(N - 1) {
        (limbs[i] as Field).assert_max_bit_size::<120>();
    }
    (limbs[N - 1] as Field).assert_max_bit_size::<MOD_BITS - (N - 1) * 120 + 6>();
}

/// Validate that `lhs - rhs` does not underflow i.e. that lhs > rhs over the integers
///
/// Compute `result = lhs - rhs` along with `borrow_flags`,
/// then constrain `result` to be a valid `BigNum` value.
///
/// ## Completeness
/// This function is complete: it will succeed for any `lhs > rhs` over the integers.
///
/// ## Soundness
/// This function is sound:
///     result[0]     = lhs[0]     - rhs[0]     + bf[0] * 2^{120}             < 2^{120}
///     result[i]     = lhs[i]     - rhs[i]     + bf[i] * 2^{120} - bf[i - 1] < 2^{120},  i = 1..N-2
///     result[N - 1] = lhs[N - 1] - rhs[N - 1]                   - bf[N - 2] < 2^{TOP_LIMB_BITS}
///     result != 0
///
/// If `lhs < rhs`, then some limb of `result` would have to borrow from a higher limb,
/// which is impossible because the top limb cannot borrow
/// Without the extra borrow, the resulting difference will be wrapped around the `Field` modulus
/// And won't satisfy the range constraint, since all the limbs are < 2^120
///
/// ## Note
/// `assert_is_not_zero_integer(result)` is crucial. Without it, we could always provide
/// two identical inputs `x`, `x` and set `borrow_flags = [false; N]`,
/// which would satisfy the limb constraints.
///
/// Since this is an integer comparison, you should validate_in_field the lhs when needed
/// to avoid accepting values that are not in canonical form (i.e. >= MOD).
/// The rhs does not need validation: since lhs > rhs and lhs < MOD, it follows that rhs < MOD.
pub(crate) fn validate_gt<let N: u32, let MOD_BITS: u32>(lhs: &[u128; N], rhs: &[u128; N]) {
    // Safety: borrow_flags are constrained by `assert_sub_no_overflow`:
    // - incorrect flags cause the computed result to fail 128-bit range checks
    // - if lhs < rhs, the subtraction overflows Field and fails range checks
    let borrow_flags: [bool; N - 1] = unsafe { compute_borrow_flags(lhs, rhs) };

    // Compute and validate the result in constrained code
    let result: [u128; N] = assert_sub_no_overflow::<N, MOD_BITS>(lhs, rhs, &borrow_flags);

    // Constrain it to be strict inequality
    assert_is_not_zero_integer(&result);
}

/// Compute the result of lhs - rhs given borrow flags and validate it
///
/// This is the constrained analog of the result computation in the unconstrained helpers.
/// Given borrow_flags, computes result such that:
///     result[0]     = lhs[0]     - rhs[0]     + bf[0] * 2^{120}
///     result[i]     = lhs[i]     - rhs[i]     + bf[i] * 2^{120} - bf[i - 1],  i = 1..N-2
///     result[N - 1] = lhs[N - 1] - rhs[N - 1]                   - bf[N - 2]
///
/// Also validates that the result is a valid BigNum value (each limb in range).
/// If lhs < rhs, the result will have a negative value (wrapped in Field) and fail validation.
fn assert_sub_no_overflow<let N: u32, let MOD_BITS: u32>(
    lhs: &[u128; N],
    rhs: &[u128; N],
    borrow_flags: &[bool; N - 1],
) -> [u128; N] {
    let mut result: [u128; N] = [0; N];

    // Compute first limb
    let limb_0: Field =
        (lhs[0] as Field) - (rhs[0] as Field) + (borrow_flags[0] as Field) * (TWO_POW_120 as Field);
    limb_0.assert_max_bit_size::<128>();
    result[0] = limb_0 as u128;

    // Compute middle limbs
    for i in 1..N - 1 {
        let limb_i: Field = (lhs[i] as Field) - (rhs[i] as Field)
            + (borrow_flags[i] as Field) * (TWO_POW_120 as Field)
            - (borrow_flags[i - 1] as Field);
        limb_i.assert_max_bit_size::<128>();
        result[i] = limb_i as u128;
    }

    // Compute last limb
    let limb_last: Field =
        (lhs[N - 1] as Field) - (rhs[N - 1] as Field) - (borrow_flags[N - 2] as Field);
    limb_last.assert_max_bit_size::<128>();
    result[N - 1] = limb_last as u128;

    // Validate that the result is a valid BigNum value (120-bit limbs, TOP_LIMB_BITS for last)
    validate_in_range::<N, MOD_BITS>(&result);

    result
}

/// Compute the result of modular subtraction given flags and validate it
///
/// Computes `result = lhs - rhs + (underflow ? modulus : 0)` given carry and borrow flags.
/// The formula for each limb is:
///     result[0]     = lhs[0]     - rhs[0]     + addend[0]     + bf[0] * 2^120 - cf[0] * 2^120
///     result[i]     = lhs[i]     - rhs[i]     + addend[i]     + bf[i] * 2^120 - cf[i] * 2^120 - bf[i-1] + cf[i-1],  i = 1..N-2
///     result[N - 1] = lhs[N - 1] - rhs[N - 1] + addend[N - 1]                               - bf[N-2] + cf[N-2]
///
/// Also validates that the result is a valid BigNum value (each limb in range).
fn compute_sub_result<let N: u32, let MOD_BITS: u32>(
    modulus: &[u128; N],
    lhs: &[u128; N],
    rhs: &[u128; N],
    carry_flags: &[bool; N - 1],
    borrow_flags: &[bool; N - 1],
    underflow: bool,
) -> [u128; N] {
    let addend: [u128; N] = if underflow { *modulus } else { [0; N] };

    let mut result: [u128; N] = [0; N];

    // Compute first limb
    let limb_0: Field = (lhs[0] as Field) - (rhs[0] as Field)
        + (addend[0] as Field)
        + (borrow_flags[0] as Field) * (TWO_POW_120 as Field)
        - (carry_flags[0] as Field) * (TWO_POW_120 as Field);
    limb_0.assert_max_bit_size::<128>();
    result[0] = limb_0 as u128;

    // Compute middle limbs
    for i in 1..N - 1 {
        let limb_i: Field = (lhs[i] as Field) - (rhs[i] as Field)
            + (addend[i] as Field)
            + (borrow_flags[i] as Field) * (TWO_POW_120 as Field)
            - (carry_flags[i] as Field) * (TWO_POW_120 as Field)
            - (borrow_flags[i - 1] as Field)
            + (carry_flags[i - 1] as Field);
        limb_i.assert_max_bit_size::<128>();
        result[i] = limb_i as u128;
    }

    // Compute last limb
    let limb_last: Field = (lhs[N - 1] as Field) - (rhs[N - 1] as Field) + (addend[N - 1] as Field)
        - (borrow_flags[N - 2] as Field)
        + (carry_flags[N - 2] as Field);
    limb_last.assert_max_bit_size::<128>();
    result[N - 1] = limb_last as u128;

    // Validate that the result is a valid BigNum value (120-bit limbs, TOP_LIMB_BITS for last)
    validate_in_range::<N, MOD_BITS>(&result);

    result
}

/// Compute the result of modular addition given flags and validate it
///
/// Computes `result = lhs + rhs - (overflow ? modulus : 0)` given carry and borrow flags.
/// The formula for each limb is:
///     result[0]     = lhs[0]     + rhs[0]     - subtrahend[0]     + bf[0] * 2^120 - cf[0] * 2^120
///     result[i]     = lhs[i]     + rhs[i]     - subtrahend[i]     + bf[i] * 2^120 - cf[i] * 2^120 - bf[i-1] + cf[i-1],  i = 1..N-2
///     result[N - 1] = lhs[N - 1] + rhs[N - 1] - subtrahend[N - 1]                               - bf[N-2] + cf[N-2]
///
/// Also validates that the result is a valid BigNum value (each limb in range).
fn compute_add_result<let N: u32, let MOD_BITS: u32>(
    modulus: &[u128; N],
    lhs: &[u128; N],
    rhs: &[u128; N],
    carry_flags: &[bool; N - 1],
    borrow_flags: &[bool; N - 1],
    overflow: bool,
) -> [u128; N] {
    let subtrahend: [u128; N] = if overflow { *modulus } else { [0; N] };

    let mut result: [u128; N] = [0; N];

    // Compute first limb
    let limb_0: Field = (lhs[0] as Field) + (rhs[0] as Field) - (subtrahend[0] as Field)
        + (borrow_flags[0] as Field) * (TWO_POW_120 as Field)
        - (carry_flags[0] as Field) * (TWO_POW_120 as Field);
    limb_0.assert_max_bit_size::<128>();
    result[0] = limb_0 as u128;

    // Compute middle limbs
    for i in 1..N - 1 {
        let limb_i: Field = (lhs[i] as Field) + (rhs[i] as Field)
            - (subtrahend[i] as Field)
            - (borrow_flags[i - 1] as Field)
            + (carry_flags[i - 1] as Field)
            + (borrow_flags[i] as Field) * (TWO_POW_120 as Field)
            - (carry_flags[i] as Field) * (TWO_POW_120 as Field);
        limb_i.assert_max_bit_size::<128>();
        result[i] = limb_i as u128;
    }

    // Compute last limb
    let limb_last: Field = (lhs[N - 1] as Field) + (rhs[N - 1] as Field)
        - (subtrahend[N - 1] as Field)
        - (borrow_flags[N - 2] as Field)
        + (carry_flags[N - 2] as Field);
    limb_last.assert_max_bit_size::<128>();
    result[N - 1] = limb_last as u128;

    // Validate that the result is a valid BigNum value (120-bit limbs, TOP_LIMB_BITS for last)
    validate_in_range::<N, MOD_BITS>(&result);

    result
}

/// Validate that `val` < `MOD`
pub fn validate_in_field<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    val: &[u128; N],
) {
    validate_gt::<N, MOD_BITS>(&params.modulus, val);
}

/// Compare two `BigNum` values, returning their `Ordering`.
///
/// Performs an integer comparison of the values `sum(limb[i] * 2^(120 * i))`,
/// **not** modular ordering.
///
/// ## Safety
/// For modular ordering both operands **must** be in `[0, MOD)`: call
/// `validate_in_field` on each operand first, otherwise representatives of the
/// same residue (e.g. `MOD` vs `0`) compare as different integers.
///
/// ## Soundness
/// `Equal` is decided on the constrained difference `a - b`, not on the limb
/// arrays. Its limbs are range-checked, so it is the integer zero exactly when
/// the two integers are equal. An operand with an unnormalised limb (for example
/// `[2^120, 0, 0]` against `[0, 1, 0]`) therefore never compares `Less` or
/// `Greater` to an equal integer.
///
/// ## Completeness
/// The difference must normalise with borrows in {0, 1}. Operands with limbs in
/// range (`from_limbs` or `validate_in_range`) always do. Other unnormalised
/// operands can make cmp fail (for example `[2^120, 0, 1]` against
/// `[0, 2^120 + 1, 0]`, the same integer); it never returns a wrong order.
pub fn cmp<let N: u32, let MOD_BITS: u32>(lhs: &[u128; N], rhs: &[u128; N]) -> Ordering {
    // Safety: underflow and borrow_flags are constrained by `assert_sub_no_overflow`:
    // - we swap (a, b) based on underflow, then compute a - b
    // - if underflow is wrong, a < b and the subtraction overflows, failing range checks
    // - if borrow_flags are wrong, the computed limbs fail 128-bit range checks
    let (underflow, borrow_flags): (bool, [bool; N - 1]) = unsafe { compute_gte_flags(lhs, rhs) };

    // if underflow is true, swap lhs and rhs so we compute larger - smaller
    let (a, b): ([u128; N], [u128; N]) = if underflow {
        (*rhs, *lhs)
    } else {
        (*lhs, *rhs)
    };

    // Enforce correctness of `underflow` by asserting that the subtraction does not overflow.
    let difference: [u128; N] = assert_sub_no_overflow::<N, MOD_BITS>(&a, &b, &borrow_flags);

    // `difference` is the integer a - b >= 0 with range-checked limbs, so it is
    // zero exactly when lhs and rhs are equal integers. A limb-array comparison
    // would call two encodings of one integer unequal.
    if is_zero_integer(&difference) {
        Ordering::equal()
    } else if underflow {
        Ordering::less()
    } else {
        Ordering::greater()
    }
}

// ------------------------------ ARITHMETIC FUNCTIONS ------------------------------

/// Negate a `BigNum` value
///
/// Computes `result = 0 - val (mod MOD)` using constrained subtraction function
///
/// All constraints and soundness details are handled inside `sub`.
pub fn neg<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    val: &[u128; N],
) -> [u128; N] {
    if std::runtime::is_unconstrained() {
        // Safety: unconstrained runtime requires no constraints
        unsafe {
            __neg(&params.modulus, val)
        }
    } else {
        sub(params, &[0; N], val)
    }
}

/// Add two `BigNum` values
///
/// Computes `result = lhs + rhs` using limb-wise addition with carry flags,
/// and an optional subtraction of `MOD` using borrow flags. The function then
/// constrains:
///   - all `result` limbs to be a valid `BigNum` value, and
///   - the addition/subtraction relation with the carry/borrow flags and the
///     `overflow_modulus` bit.
///
/// ## Assumptions
/// - All limbs of `lhs`, `rhs` and `MOD` are valid `BigNum` limbs
///   (120-bit for non-top limbs, `TOP_LIMB_BITS` for the top limb).
/// - Semantically, we intend to use this only with `0 <= lhs, rhs < MOD`,
///   even though the limb/range constraints allow values up to `< 2^{MOD_BITS}`.
///
/// ## Soundness (intended relation)
/// This function constrains the following equations:
///
///     result[0]     = lhs[0]     + rhs[0]
///                     - sub[0]
///                     + bf[0] * 2^{120}
///                     - cf[0]                                        < 2^{120}
///
///     result[i]     = lhs[i]     + rhs[i]
///                     - sub[i]
///                     + bf[i] * 2^{120}  - bf[i - 1]
///                     - cf[i] * 2^{120}  + cf[i - 1]                 < 2^{120},
///                     for i = 1..N-2
///
///     result[N - 1] = lhs[N - 1] + rhs[N - 1]
///                     - sub[N - 1]
///                     - bf[N - 2]
///                     + cf[N - 2]                                   < 2^{TOP_LIMB_BITS}
///
/// where:
///   - `bf[i]` are the borrow flags of the optional subtraction,
///   - `cf[i]` are the carry flags of the addition, and
///   - `sub` is either the zero vector or `MOD`, depending on the
///     `overflow_modulus` flag:
///         * `overflow_modulus = 0`  =>  `sub = 0`
///         * `overflow_modulus = 1`  =>  `sub = MOD`
///
/// If `lhs`, `rhs` and `MOD` are valid `BigNum` limbs and the witness for
/// `(bf, cf, overflow_modulus)` is the honest one produced by `compute_add_flags`,
/// these constraints enforce:
///   - a valid limb-wise carry chain for `lhs + rhs`, and
///   - a valid limb-wise subtraction chain for either `lhs + rhs` or
///     `lhs + rhs - MOD`, with no underflow in any limb.
///
/// Under these assumptions the constrained result equals:
///
///     result = lhs + rhs (mod MOD)
///
/// in the intended arithmetic.
///
/// ## Limitations / extra satisfying witnesses
///
/// The constraint system itself does **not** uniquely determine the carry/borrow
/// flags nor the `overflow_modulus` bit:
///
/// - For each limb `i`, `bf[i]` and `cf[i]` only appear in the combination
///   `bf[i] * 2^{120} - cf[i] * 2^{120}`. This means that both
///
///       (bf[i], cf[i]) = (0, 0)  and  (bf[i], cf[i]) = (1, 1)
///
///   give the same contribution to the equation. As a result, there are multiple
///   valid flag assignments for the *same* `lhs`, `rhs`, `sub` and `result`.
///
/// - More importantly, if `lhs + rhs` is greater than `MOD` but still strictly
///   less than `2^{MOD_BITS}`, there exist *spurious* witnesses where:
///     * `overflow_modulus` is set inconsistently with the true arithmetic
///       overflow, and
///     * the `(bf, cf)` flags are adjusted accordingly,
///
///   such that all equations above still hold and all `result` limbs remain
///   within range. In particular, when
///
///       lhs + rhs + MOD < 2^{MOD_BITS},
///
///   a malicious prover can "hide" an extra `MOD` inside the choice of
///   `overflow_modulus`, `bf` and `cf`, so that the circuit is satisfied by a
///   witness
///
/// ## Completeness
///
/// For inputs in the range `0 <= lhs, rhs < MOD` and honest flags from
/// `compute_add_flags`, the constraints are complete: every valid `BigNum` sum
/// `lhs + rhs (mod MOD)` admits a satisfying assignment.
///
/// Inputs with `lhs` or `rhs` in `[MOD, 2^{MOD_BITS})` are still representable
/// as limb arrays and may admit satisfying witnesses, but then the operation
/// no longer corresponds to a unique, well-defined addition in the field
/// `Z / MOD Z`. Such uses are outside the intended semantics of this function.
pub fn add<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    lhs: &[u128; N],
    rhs: &[u128; N],
) -> [u128; N] {
    if std::runtime::is_unconstrained() {
        // Safety: unconstrained runtime requires no constraints
        unsafe {
            __add(&params.modulus, lhs, rhs)
        }
    } else {
        let modulus = params.modulus;
        // Safety: flags are constrained by `compute_add_result`:
        // - incorrect flags cause computed limbs to fail 128-bit range checks
        // - wrong overflow causes result to be off by modulus, failing `validate_in_range`
        let (carry_flags, borrow_flags, overflow): ([bool; N - 1], [bool; N - 1], bool) =
            unsafe { compute_add_flags(&modulus, lhs, rhs) };

        // Compute and validate the result in constrained code
        compute_add_result::<N, MOD_BITS>(&modulus, lhs, rhs, &carry_flags, &borrow_flags, overflow)
    }
}

/// Subtract two `BigNum` values
///
/// Computes `result = lhs - rhs` using limb-wise subtraction with borrow flags,
/// and an optional addition of `MOD` using carry flags. The function then
/// constrains:
///   - all `result` limbs to be a valid `BigNum` value, and
///   - the subtraction/addition relation with the carry/borrow flags and the
///     `underflow_modulus` bit.
///
/// ## Assumptions
/// - All limbs of `lhs`, `rhs` and `MOD` are valid `BigNum` limbs
///   (120-bit for non-top limbs, `TOP_LIMB_BITS` for the top limb).
/// - Semantically, we intend to use this only with `0 <= lhs, rhs < MOD`,
///   even though the limb/range constraints allow values up to `< 2^{MOD_BITS}`.
///
/// ## Soundness (intended relation)
/// This function constrains the following equations:
///
///     result[0]     = lhs[0]     - rhs[0]
///                     + add[0]
///                     + bf[0] * 2^{120}
///                     - cf[0]                                        < 2^{120}
///
///     result[i]     = lhs[i]     - rhs[i]
///                     + add[i]
///                     + bf[i] * 2^{120}  - bf[i - 1]
///                     - cf[i] * 2^{120}  + cf[i - 1]                 < 2^{120},
///                     for i = 1..N-2
///
///     result[N - 1] = lhs[N - 1] - rhs[N - 1]
///                     + add[N - 1]
///                     - bf[N - 2]
///                     + cf[N - 2]                                   < 2^{TOP_LIMB_BITS}
///
/// where:
///   - `bf[i]` are the borrow flags of the subtraction,
///   - `cf[i]` are the carry flags of the optional addition, and
///   - `add` is either the zero vector or `MOD`, depending on the
///     `underflow_modulus` flag:
///         * `underflow_modulus = 0`  =>  `add = 0`
///         * `underflow_modulus = 1`  =>  `add = MOD`
///
/// If `lhs`, `rhs` and `MOD` are valid `BigNum` limbs and the witness for
/// `(bf, cf, underflow_modulus)` is the honest one produced by `compute_sub_flags`,
/// these constraints enforce:
///   - a valid limb-wise borrow chain for `lhs - rhs`, and
///   - a valid limb-wise addition chain for either `lhs - rhs` or
///     `lhs - rhs + MOD`, with no underflow in any limb.
///
/// Under these assumptions the constrained result equals:
///
///     result = lhs - rhs (mod MOD)
///
/// in the intended arithmetic.
///
/// ## Limitations / extra satisfying witnesses
///
/// The constraint system itself does **not** uniquely determine the carry/borrow
/// flags nor the `underflow_modulus` bit:
///
/// - For each limb `i`, `bf[i]` and `cf[i]` only appear in the combination
///   `bf[i] * 2^{120} - cf[i] * 2^{120}`. This means that both
///
///       (bf[i], cf[i]) = (0, 0)  and  (bf[i], cf[i]) = (1, 1)
///
///   give the same contribution to the equation. As a result, there are multiple
///   valid flag assignments for the *same* `lhs`, `rhs`, `add` and `result`.
///
/// - More importantly, when `lhs < rhs`, the true field result is
///
///       lhs - rhs + MOD,
///
///   and as long as
///
///       lhs - rhs + MOD < 2^{MOD_BITS},
///
///   a malicious prover can:
///     * set `underflow_modulus` inconsistently with the true underflow, and
///     * adjust the `(bf, cf)` flags accordingly,
///
///   such that all equations above still hold and all `result` limbs remain
///   within range. In other words, the circuit can be satisfied by a witness
///   that does **not** correspond to the unique intended subtraction modulo
///   `MOD` for some inputs with `lhs < rhs`.
///
/// ## Completeness
///
/// For inputs in the range `0 <= lhs, rhs < MOD` and honest flags from
/// `compute_sub_flags`, the constraints are complete: every valid `BigNum`
/// difference `lhs - rhs (mod MOD)` admits a satisfying assignment.
///
/// Inputs with `lhs` or `rhs` in `[MOD, 2^{MOD_BITS})` are still representable
/// as limb arrays and may admit satisfying witnesses, but then the operation
/// no longer corresponds to a unique, well-defined subtraction in the field
/// `Z / MOD Z`. Such uses are outside the intended semantics of this function.
pub fn sub<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    lhs: &[u128; N],
    rhs: &[u128; N],
) -> [u128; N] {
    if std::runtime::is_unconstrained() {
        // Safety: unconstrained runtime requires no constraints
        unsafe {
            __sub(&params.modulus, lhs, rhs)
        }
    } else {
        let modulus = params.modulus;
        // Safety: flags are constrained by `compute_sub_result`:
        // - incorrect flags cause computed limbs to fail 128-bit range checks
        // - wrong underflow causes result to be off by modulus, failing `validate_in_range`
        let (carry_flags, borrow_flags, underflow): ([bool; N - 1], [bool; N - 1], bool) =
            unsafe { compute_sub_flags(&modulus, lhs, rhs) };

        // Compute and validate the result in constrained code
        compute_sub_result::<N, MOD_BITS>(
            &modulus,
            lhs,
            rhs,
            &carry_flags,
            &borrow_flags,
            underflow,
        )
    }
}

/// Compute the `BigNum` multiplication
///
/// Computes `result = lhs * rhs (mod MOD)` by:
///   1. Computing `result` out of circuit via `__mul`.
///   2. Constraining the quadratic relation `lhs * rhs - result = 0` with
///      `evaluate_quadratic_expression`.
///
/// ## Soundness
/// Soundness reduces to `evaluate_quadratic_expression` for the relation
/// `lhs * rhs - result = 0`
///
/// ## Note
/// When possible, prefer expressing your computation directly as a quadratic
///   relation and calling `evaluate_quadratic_expression` instead of using `mul`
pub fn mul<let N: u32, let MOD_BITS: u32>(
    params: BigNumParams<N, MOD_BITS>,
    lhs: [u128; N],
    rhs: [u128; N],
) -> [u128; N] {
    // Safety: we constrain the multiplication result immediately after
    let result: [u128; N] = unsafe { __mul::<N, MOD_BITS>(&params, &lhs, &rhs) };
    if !std::runtime::is_unconstrained() {
        // lhs * rhs - result = 0
        let lhs_terms: [[[u128; N]; 1]; 1] = [[lhs]];
        let lhs_flags: [[bool; 1]; 1] = [[false]];
        let rhs_terms: [[[u128; N]; 1]; 1] = [[rhs]];
        let rhs_flags: [[bool; 1]; 1] = [[false]];
        let linear_terms: [[u128; N]; 1] = [result];
        let linear_flags: [bool; 1] = [true];
        evaluate_quadratic_expression::<N, MOD_BITS, 1, 1, 1, 1>(
            &params,
            &lhs_terms,
            &lhs_flags,
            &rhs_terms,
            &rhs_flags,
            &linear_terms,
            &linear_flags,
        );
    }
    result
}

/// Compute the `BigNum` squaring
///
/// Computes `result = val * val (mod MOD)` by:
///   1. Computing `result` out of circuit via `__sqr`.
///   2. Constraining the quadratic relation `val * val - result = 0` with
///      `evaluate_quadratic_expression`.
///
/// ## Soundness
/// Soundness reduces to `evaluate_quadratic_expression` for the relation
/// `val * val - result = 0`
///
/// ## Note
/// When possible, prefer expressing your computation directly as a quadratic
///   relation and calling `evaluate_quadratic_expression` instead of using `sqr`
pub fn sqr<let N: u32, let MOD_BITS: u32>(
    params: BigNumParams<N, MOD_BITS>,
    val: [u128; N],
) -> [u128; N] {
    // Safety: we constrain the multiplication result immediately after
    let result: [u128; N] = unsafe { __sqr::<_, MOD_BITS>(&params, &val) };
    if !std::runtime::is_unconstrained() {
        // val * val - result = 0
        let lhs_terms: [[[u128; N]; 1]; 1] = [[val]];
        let lhs_flags: [[bool; 1]; 1] = [[false]];
        let rhs_terms: [[[u128; N]; 1]; 1] = [[val]];
        let rhs_flags: [[bool; 1]; 1] = [[false]];
        let linear_terms: [[u128; N]; 1] = [result];
        let linear_flags: [bool; 1] = [true];
        evaluate_quadratic_expression::<N, MOD_BITS, 1, 1, 1, 1>(
            &params,
            &lhs_terms,
            &lhs_flags,
            &rhs_terms,
            &rhs_flags,
            &linear_terms,
            &linear_flags,
        );
    }
    result
}

/// Compute the `BigNum` division
///
/// Computes `result = lhs * rhs^{-1} (mod MOD)` by:
///   1. Computing `result` out of circuit via `__div`.
///   2. Constraining the quadratic relation `result * rhs - lhs = 0` with
///      `evaluate_quadratic_expression`.
///   3. Enforcing `rhs != 0 (mod MOD)`.
///
/// ## Soundness
/// Soundness reduces to `evaluate_quadratic_expression` for the relation
/// `result * rhs - lhs = 0`, together with the non-zero check on `rhs` and the
/// assumption that `MOD` has multiplicative inverses for all non-zero elements
/// (`params.has_multiplicative_inverse = true`).
///
/// ## Note
/// - This is **expensive** in witness time due to modular inversion.
/// - When possible, prefer expressing your computation directly as a quadratic
///   relation and calling `evaluate_quadratic_expression` instead of using `div`.
/// - In the unconstrained runtime, the behavior of `__div` on zero divisors is
///   not constrained by this function.
pub fn div<let N: u32, let MOD_BITS: u32>(
    params: BigNumParams<N, MOD_BITS>,
    lhs: [u128; N],
    rhs: [u128; N],
) -> [u128; N] {
    assert(
        params.has_multiplicative_inverse,
        "BigNum has no multiplicative inverse. Use udiv for unsigned integer division",
    );
    // Safety: We constrain the result of division immediately after
    let result: [u128; N] = unsafe { __div::<_, MOD_BITS>(&params, &lhs, &rhs) };
    if !std::runtime::is_unconstrained() {
        // result * rhs - lhs = 0
        let lhs_terms: [[[u128; N]; 1]; 1] = [[result]];
        let lhs_flags: [[bool; 1]; 1] = [[false]];
        let rhs_terms: [[[u128; N]; 1]; 1] = [[rhs]];
        let rhs_flags: [[bool; 1]; 1] = [[false]];
        let linear_terms: [[u128; N]; 1] = [lhs];
        let linear_flags: [bool; 1] = [true];
        evaluate_quadratic_expression::<N, MOD_BITS, 1, 1, 1, 1>(
            &params,
            &lhs_terms,
            &lhs_flags,
            &rhs_terms,
            &rhs_flags,
            &linear_terms,
            &linear_flags,
        );
        assert_is_not_zero(&params, &rhs);
    }
    result
}

/// Compute the `BigNum` integer division with remainder
///
/// Computes `quotient = floor(numerator / divisor)` and
/// `remainder = numerator % divisor` by:
///   1. Computing `(quotient, remainder)` out of circuit via `__udiv_mod`.
///   2. Constraining the quadratic relation
///        quotient * divisor + remainder - numerator = 0
///      with `validate_udiv_mod_expression`.
///   3. Enforcing `remainder < divisor`.
///
/// ## Soundness
/// Soundness reduces to `validate_udiv_mod_expression` for the relation
///     quotient * divisor + remainder - numerator = 0,
/// together with `remainder < divisor` check enforced via `validate_gt`
/// and `validate_in_field` for divisor to be strictly less than MOD
///
/// Under these checks, any satisfying assignment corresponds to a valid
/// integer division `numerator = quotient * divisor + remainder` with
/// `0 <= remainder < divisor < MOD`
/// `0 <= numerator < MOD`
///
/// ## Note
/// Enforcing `divisor != 0` is not necessary. `remainder < divisor`
/// Already enforces this.
pub fn udiv_mod<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    numerator: &[u128; N],
    divisor: &[u128; N],
) -> ([u128; N], [u128; N]) {
    // Safety: We constrain the result of __udiv_mod immediately after
    let (quotient, remainder): ([u128; N], [u128; N]) = unsafe { __udiv_mod(numerator, divisor) };
    if !std::runtime::is_unconstrained() {
        // quotient * divisor + remainder - numerator = 0
        validate_udiv_mod_expression::<N, MOD_BITS>(numerator, divisor, &quotient, &remainder);
        // remainder < divisor
        validate_gt::<N, MOD_BITS>(divisor, &remainder);
        // divisor is in canonical representation
        validate_in_field(params, divisor);
        // numerator is in canonical representation
        validate_in_field(params, numerator);
    }
    (quotient, remainder)
}

/// Unsafe version of `udiv_mod`.
///
/// Does not call `validate_in_field` on the numerator or divisor.
///
/// ## Safety
/// Both `numerator` and `divisor` **must** already be in canonical form (i.e. in `[0, MOD)`).
/// Use this variant when the inputs have already been validated via `validate_in_field`
/// (e.g. as outputs of other constrained operations) to avoid redundant checks.
pub fn udiv_mod_unsafe<let N: u32, let MOD_BITS: u32>(
    numerator: &[u128; N],
    divisor: &[u128; N],
) -> ([u128; N], [u128; N]) {
    // Safety: We constrain the result of __udiv_mod immediately after
    let (quotient, remainder): ([u128; N], [u128; N]) = unsafe { __udiv_mod(numerator, divisor) };
    if !std::runtime::is_unconstrained() {
        // quotient * divisor + remainder - numerator = 0
        validate_udiv_mod_expression::<N, MOD_BITS>(numerator, divisor, &quotient, &remainder);
        // remainder < divisor
        validate_gt::<N, MOD_BITS>(divisor, &remainder);
    }
    (quotient, remainder)
}

/// Compute the `BigNum` integer division.
///
/// Returns `floor(numerator / divisor)`.
/// All constraints and soundness details are handled inside `udiv_mod`.
pub fn udiv<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    numerator: &[u128; N],
    divisor: &[u128; N],
) -> [u128; N] {
    udiv_mod::<N, MOD_BITS>(params, numerator, divisor).0
}

/// Unsafe version of `udiv`.
///
/// Returns `floor(numerator / divisor)`.
/// All constraints and soundness details are handled inside `udiv_mod_unsafe`.
///
/// ## Safety
/// Both `numerator` and `divisor` **must** already be in canonical form (i.e. in `[0, MOD)`).
pub fn udiv_unsafe<let N: u32, let MOD_BITS: u32>(
    numerator: &[u128; N],
    divisor: &[u128; N],
) -> [u128; N] {
    udiv_mod_unsafe::<N, MOD_BITS>(numerator, divisor).0
}

/// Compute the `BigNum` remainder.
///
/// Returns `numerator % divisor`.
/// All constraints and soundness details are handled inside `udiv_mod`.
pub fn umod<let N: u32, let MOD_BITS: u32>(
    params: &BigNumParams<N, MOD_BITS>,
    numerator: &[u128; N],
    divisor: &[u128; N],
) -> [u128; N] {
    udiv_mod::<N, MOD_BITS>(params, numerator, divisor).1
}

/// Unsafe version of `umod`.
///
/// Returns `numerator % divisor`.
/// All constraints and soundness details are handled inside `udiv_mod_unsafe`.
///
/// ## Safety
/// Both `numerator` and `divisor` **must** already be in canonical form (i.e. in `[0, MOD)`).
pub fn umod_unsafe<let N: u32, let MOD_BITS: u32>(
    numerator: &[u128; N],
    divisor: &[u128; N],
) -> [u128; N] {
    udiv_mod_unsafe::<N, MOD_BITS>(numerator, divisor).1
}

mod test_multilimb_comparisons {
    use crate::{BigNum, BLS12_381_Fq, MNT6_753_Fq, RuntimeBigNum};
    use crate::constants::{GRUMPKIN_MODULUS, TWO_POW_120};
    use crate::params::BigNumParams;

    fn check_aliases<T: BigNum>() {
        let zero = T::zero();
        let one = T::one();
        let modulus = T::modulus();
        let mut above = modulus.get_limbs();
        above[0] += 1;
        let above = T::from_limbs(above);
        let mut below = modulus.get_limbs();
        below[0] -= 1;
        let below = T::from_limbs(below);
        assert(zero == modulus);
        assert(modulus == zero);
        assert(one == above);
        assert(above == one);
        assert(zero != above);
        assert(above != zero);
        assert(one != modulus);
        assert(modulus != one);
        below.assert_is_not_equal(&zero);
        zero.assert_is_not_equal(&below);
        above.assert_is_not_equal(&zero);
        zero.assert_is_not_equal(&above);
        modulus.assert_is_not_equal(&one);
        one.assert_is_not_equal(&modulus);
        let mut maximum = [TWO_POW_120 - 1; T::N];
        maximum[T::N - 1] = (1u128 << ((T::MOD_BITS - 120 * (T::N - 1)) as u128)) - 1;
        let maximum = T::from_limbs(maximum);
        assert(maximum == maximum);
        maximum.assert_is_not_equal(&zero);
    }

    fn check_native_alias<T: BigNum>() {
        let mut limbs = T::zero().get_limbs();
        for i in 0..3 {
            limbs[i] = GRUMPKIN_MODULUS[i];
        }
        let native = T::from_limbs(limbs);
        native.validate_in_field();
        assert(native != T::zero());
        assert(T::zero() != native);
        native.assert_is_not_equal(&T::zero());
        T::zero().assert_is_not_equal(&native);
        let near = native + T::one();
        near.assert_is_not_equal(&T::zero());
    }

    #[test]
    fn multilimb_compare_four_limb_aliases() {
        check_aliases::<BLS12_381_Fq>();
    }

    #[test]
    fn multilimb_compare_seven_limb_aliases() {
        check_aliases::<MNT6_753_Fq>();
    }

    #[test]
    fn multilimb_compare_four_limb_native_alias() {
        check_native_alias::<BLS12_381_Fq>();
    }

    #[test]
    fn multilimb_compare_seven_limb_native_alias() {
        check_native_alias::<MNT6_753_Fq>();
    }

    #[test]
    fn multilimb_compare_two_limb_prime() {
        // The SECP128r1 field prime is 2^128-2^97-1; q+1 fits its 128-bit bound.
        let params = BigNumParams::<2, 128>::new(
            true,
            [1329227837328590844375131873192443903, 255],
            [158456325102315651516285845521, 256],
        );
        let zero = RuntimeBigNum::zero(params);
        let one = RuntimeBigNum::one(params);
        let modulus = RuntimeBigNum::from_array(params, params.modulus);
        let above = RuntimeBigNum::from_array(params, [1329227837328590844375131873192443904, 255]);
        assert(zero == modulus);
        assert(modulus == zero);
        assert(one == above);
        assert(above == one);
        assert(zero != above);
        assert(above != zero);
        above.assert_is_not_equal(&zero);
        zero.assert_is_not_equal(&above);
    }

    #[test]
    fn multilimb_compare_one_limb_runtime() {
        // Runtime constructors/comparisons support this normalized prime.
        // This does not extend the static BigNum single-limb arithmetic contract.
        let params = BigNumParams::<1, 7>::new(true, [97], [168]);
        let zero = RuntimeBigNum::zero(params);
        let one = RuntimeBigNum::one(params);
        let modulus = RuntimeBigNum::from_array(params, [97]);
        let above = RuntimeBigNum::from_array(params, [98]);
        assert(zero == modulus);
        assert(modulus == zero);
        assert(one == above);
        assert(above == one);
        zero.assert_is_not_equal(&above);
        above.assert_is_not_equal(&zero);
    }

    #[test]
    fn multilimb_compare_rejects_final_carry() {
        // The helper must not mistake a wrapped small+MOD for integer equality.
        let modulus = [TWO_POW_120 - 1; 4];
        let small = modulus;
        let large = [TWO_POW_120 - 2, TWO_POW_120 - 1, TWO_POW_120 - 1, TWO_POW_120 - 1];
        assert(!super::equal_modulus_offset(&large, &small, &modulus, 1));
    }

    #[test(should_fail_with = "assert_is_not_equal fail")]
    fn multilimb_compare_equal_alias_rejected_by_inequality() {
        let mut alias = BLS12_381_Fq::modulus().get_limbs();
        alias[0] += 1;
        BLS12_381_Fq::one().assert_is_not_equal(&BLS12_381_Fq::from_limbs(alias));
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn multilimb_compare_malformed_low_rejected() {
        let params = BLS12_381_Fq::params();
        super::assert_is_not_equal(&params, &[TWO_POW_120, 0, 0, 0], &[0; 4]);
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn multilimb_compare_malformed_top_rejected() {
        let params = BLS12_381_Fq::params();
        // Generic comparison permits one extra top bit; 1<<22 is outside it.
        assert(!super::eq(&params, &[0, 0, 0, 1 << 22], &[0; 4]));
    }
    #[test]
    fn multilimb_compare_accepts_old_top_boundary() {
        // One extra top bit is intentional for comparison-only lazy aliases.
        let x = BLS12_381_Fq::from_limbs_unsafe([0, 0, 0, 1 << 21]);
        assert(x != BLS12_381_Fq::zero());
        assert(BLS12_381_Fq::zero() != x);
        x.assert_is_not_equal(&BLS12_381_Fq::zero());
    }

    #[test]
    fn multilimb_compare_two_and_three_modulus_offsets() {
        // Equality needs normalization, not primality. q=2^360 has TOP_BITS=1.
        let params = BigNumParams::<4, 361>::new(false, [0, 0, 0, 1], [0, 0, 0, 4]);
        let zero = RuntimeBigNum::zero(params);
        let one = RuntimeBigNum::one(params);
        for factor in 1..4 {
            let alias = RuntimeBigNum { limbs: [0, 0, 0, factor as u128], params };
            let neighbor = RuntimeBigNum { limbs: [1, 0, 0, factor as u128], params };
            assert(alias == zero);
            assert(zero == alias);
            assert(neighbor == one);
            assert(one == neighbor);
            assert(neighbor != zero);
            assert(zero != neighbor);
            neighbor.assert_is_not_equal(&zero);
            zero.assert_is_not_equal(&neighbor);
        }
    }

    #[test]
    fn multilimb_compare_full_width_top_carry() {
        // q=2^240-17, with TOP_BITS=120. 2q needs a 121-bit top limb.
        let params = BigNumParams::<2, 240>::new(
            false,
            [TWO_POW_120 - 17, TWO_POW_120 - 1],
            [17, TWO_POW_120],
        );
        let zero = RuntimeBigNum::zero(params);
        let alias = RuntimeBigNum { limbs: [TWO_POW_120 - 34, 2 * TWO_POW_120 - 1], params };
        assert(alias == zero);
        assert(zero == alias);
        let maximum = RuntimeBigNum { limbs: [TWO_POW_120 - 1, 2 * TWO_POW_120 - 1], params };
        let remainder = RuntimeBigNum::from_array(params, [33, 0]);
        assert(maximum == remainder);
        assert(remainder == maximum);
        maximum.assert_is_not_equal(&zero);
    }

    #[test(should_fail_with = "assert_is_not_equal fail")]
    fn multilimb_compare_three_modulus_inequality_rejected() {
        let params = BigNumParams::<4, 361>::new(false, [0, 0, 0, 1], [0, 0, 0, 4]);
        let alias = RuntimeBigNum { limbs: [0, 0, 0, 3], params };
        alias.assert_is_not_equal(&RuntimeBigNum::zero(params));
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn multilimb_compare_unnormalized_modulus_rejected() {
        let mut params = BLS12_381_Fq::params();
        params.modulus[3] = 0;
        assert(super::eq(&params, &[0; 4], &[0; 4]));
    }

    #[test(should_fail_with = "call to assert_max_bit_size")]
    fn multilimb_compare_malformed_modulus_limb_rejected() {
        let mut params = BLS12_381_Fq::params();
        params.modulus[0] = TWO_POW_120;
        assert(super::eq(&params, &[0; 4], &[0; 4]));
    }

    #[test(should_fail_with = "unsupported comparison geometry")]
    fn multilimb_compare_unsupported_layout_rejected() {
        let params = BigNumParams::<1, 121> {
            has_multiplicative_inverse: false,
            modulus: [TWO_POW_120],
            double_modulus: [0],
            redc_param: [0],
        };
        assert(super::eq(&params, &[0], &[0]));
    }

}
