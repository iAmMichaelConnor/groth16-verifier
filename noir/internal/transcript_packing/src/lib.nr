//! Internal: injective packing of bounded Fq limbs into Field words for the
//! verifiers' transcripts and key commitments.
// Encoding helper only: callers MUST constrain every input limb to120/120/14
// bits before using this output as a cryptographic commitment. Strict<q remains
// the caller's separate canonicality policy. Counts and padding are fixed by N.
pub fn pack_bounded<let N: u32>(values: [[u128; 3]; N]) -> [Field; N + (N + 17) / 18] {
    let mut words = [0; N + (N + 17) / 18];
    for i in 0..N {
        words[i] =
            values[i][0] as Field + (values[i][1] as Field) * 0x1000000000000000000000000000000;
    }
    for group in 0..(N + 17) / 18 {
        let mut factor: Field = 1;
        for j in 0..18 {
            if group * 18 + j < N {
                words[N + group] = words[N + group] + (values[group * 18 + j][2] as Field) * factor;
            }
            factor = factor * 16384;
        }
    }
    words
}

#[test]
fn packs_low_words_then_grouped_top_limbs() {
    let radix: Field = 0x1000000000000000000000000000000;
    // One coefficient: [low + 2^120 * middle, top].
    assert(pack_bounded([[1, 2, 3]]) == [1 + 2 * radix, 3]);
    // Nineteen coefficients need two top-limb groups: 18 limbs in the first
    // (weights 2^(14 j)) and the last alone in the second.
    let mut values = [[0; 3]; 19];
    values[0] = [7, 0, 1];
    values[1] = [0, 0, 2];
    values[17] = [0, 0, 3];
    values[18] = [0, 5, 4];
    let packed = pack_bounded(values);
    assert(packed[0] == 7);
    assert(packed[18] == 5 * radix);
    let mut weight: Field = 1;
    for _ in 0..17 {
        weight *= 16384;
    }
    assert(packed[19] == 1 + 2 * 16384 + 3 * weight);
    assert(packed[20] == 4);
}

#[test]
fn distinct_bounded_encodings_pack_differently() {
    // A unit moved between the low and middle limb, or between two top limbs,
    // changes the packed transcript.
    assert(pack_bounded([[0, 1, 0]]) != pack_bounded([[1, 0, 0]]));
    assert(pack_bounded([[0, 0, 1], [0, 0, 0]]) != pack_bounded([[0, 0, 0], [0, 0, 1]]));
}
