//! Trusted packed pair representation; finite origins and valid curve points are caller invariants.
use bignum::{BigNum, BN254_Fq as Fp};

pub unconstrained fn unpack_hint(words: [Field; 5]) -> ([[u128; 3]; 4], bool) {
    let mut raw = [[0; 3]; 4];
    let high = words[4] as u64;
    for i in 0..4 {
        let bytes: [u8; 32] = words[i].to_le_bytes();
        let mut low: u128 = 0;
        let mut middle: u128 = 0;
        for j in 0..15 {
            low = low * 256 + bytes[14 - j] as u128;
            middle = middle * 256 + bytes[29 - j] as u128;
        }
        raw[i] = [low, middle, ((high >> (14 * i as u64)) & 16383) as u128];
    }
    (raw, ((high >> 56) & 1) == 1)
}

// Public within this private component to allow direct malformed-hint probes.
// Every hint limb is range checked before recomposition; equality cannot wrap
// because low words are <2^240 and the last word is <2^57, both below Fr.
// Equations: words[i]=raw[i][0]+2^120*raw[i][1] (i<4), and
// words[4]=sum_i 2^(14*i)*raw[i][2]+2^56*flag. The Fp constructor
// supplies 120/120/14-bit bounds first, so these are injective integer
// encodings (<2^240 and <2^57), despite being checked in native Fr.
// This binds representation only: the trusted table supplies curve validity
// and C_j=K-[2^60]O_j. Arbitrary decode_given words do not establish either.
pub fn decode_given(
    words: [Field; 5],
    raw: [[u128; 3]; 4],
    correction_infinity: bool,
) -> ([Fp; 4], bool) {
    let values = raw.map(Fp::from_limbs);
    let radix: Field = 1329227995784915872903807060280344576;
    let mut high: Field = 0;
    for i in 0..4 {
        assert(
            words[i] == raw[i][0] as Field + radix * (raw[i][1] as Field),
            "packed offset low mismatch",
        );
        high += (raw[i][2] as Field) * ((1u64 << (14 * i as u64)) as Field);
    }
    high += (correction_infinity as Field) * 72057594037927936;
    assert(words[4] == high, "packed offset high mismatch");
    (values, correction_infinity)
}

// One checked index selects the entire row, hence the origin AND its matching
// correction. A hint cannot independently replace either point or infinity flag.
// Generic C is a shape parameter; sufficient distinct origins are a separate
// caller invariant, C=136*N+1 for the fixed BN254 16-window schedule.
pub fn select<let C: u32>(table: [[Field; 5]; C], index: u32) -> ([Fp; 4], bool) {
    assert(index < C, "offset index out of range");
    let words = table[index];
    // Safety: every output limb and the flag are bound by exact decode_given.
    let (raw, flag) = unsafe { unpack_hint(words) };
    decode_given(words, raw, flag)
}

mod tests {
    use super::{decode_given, select, unpack_hint};
    use bignum::{BigNum, BN254_Fq as Fp};

    // Row for origin (1, 2) and correction (3, 4) with top limbs 5, 6, 7, 8 and
    // the correction-infinity flag set: words[i] = low + 2^120 * middle and
    // words[4] = 5 + 6 * 2^14 + 7 * 2^28 + 8 * 2^42 + 2^56.
    global RADIX: Field = 1329227995784915872903807060280344576;
    global RAW: [[u128; 3]; 4] = [[1, 9, 5], [2, 10, 6], [3, 11, 7], [4, 12, 8]];
    global HIGH: Field = 72092780289163269;

    fn row() -> [Field; 5] {
        [1 + 9 * RADIX, 2 + 10 * RADIX, 3 + 11 * RADIX, 4 + 12 * RADIX, HIGH]
    }

    #[test]
    fn select_decodes_exactly_the_indexed_row() {
        let table = [[0; 5], row()];
        let (values, flag) = select(table, 1);
        assert(flag);
        for i in 0..4 {
            assert(values[i] == Fp::from_limbs(RAW[i]));
        }
        // Safety: test-only inspection of the hint.
        let (raw, hinted_flag) = unsafe { unpack_hint(row()) };
        assert(raw == RAW);
        assert(hinted_flag);
        let (_, zero_flag) = select(table, 0);
        assert(!zero_flag);
    }

    #[test(should_fail_with = "offset index out of range")]
    fn select_rejects_an_index_past_the_table() {
        let _ = select([row()], std::hint::black_box(1));
    }

    #[test(should_fail_with = "packed offset low mismatch")]
    fn decode_rejects_a_changed_coordinate_limb() {
        let mut raw = RAW;
        raw[2][0] += 1;
        let _ = decode_given(row(), raw, true);
    }

    #[test(should_fail_with = "packed offset high mismatch")]
    fn decode_rejects_a_flipped_infinity_flag() {
        let _ = decode_given(row(), RAW, false);
    }

    #[test(should_fail_with = "packed offset high mismatch")]
    fn decode_rejects_a_changed_top_limb() {
        let mut raw = RAW;
        raw[3][2] += 1;
        let _ = decode_given(row(), raw, true);
    }
}
