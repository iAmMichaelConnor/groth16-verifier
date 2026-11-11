//! Fixed BN254 GLV scalar preparation, generic over the public-input count.
global LAMBDA: Field =
    21888242871839275217838484774961031246154997185409878258781734729429964517155;
global BIAS: Field = 85070591730234615865843651857942052864;
global CHUNK_RADIX: Field = 18446744073709551616;

// GLV: phi(P)=[LAMBDA]P, so s=(u-BIAS)+LAMBDA*(v-BIAS) mod r.
// Components are <2^127. Each lo+2^64*hi is also <2^127<r; its Field
// equality is therefore exact integer recomposition, not a modular alias.
// Bounds are on witnesses, not assumptions about split_chunks' honest output.
// GLV reference: https://link.springer.com/chapter/10.1007/3-540-44647-8_11
// Application-specific hash policies belong to their integration wrappers.
pub fn check_glv_and_chunks<let N: u32>(
    inputs: [Field; N],
    components: [[Field; 2]; N],
    chunks: [[Field; 2]; 2 * N],
) {
    let mut flat = [0; 2 * N];
    for i in 0..N {
        components[i][0].assert_max_bit_size::<127>();
        components[i][1].assert_max_bit_size::<127>();
        assert(
            components[i][0] + LAMBDA * components[i][1] - BIAS * (1 + LAMBDA) == inputs[i],
            "Invalid GLV decomposition",
        );
        flat[2 * i] = components[i][0];
        flat[2 * i + 1] = components[i][1];
    }
    for i in 0..2 * N {
        chunks[i][0].assert_max_bit_size::<64>();
        chunks[i][1].assert_max_bit_size::<63>();
        assert(
            chunks[i][0] + CHUNK_RADIX * chunks[i][1] == flat[i],
            "Invalid fixed-base chunk recomposition",
        );
    }
}

// Order is [u_lo,u_hi,v_lo,v_hi] per input. The caller's bases must be
// [P,[2^64]P,phi(P),[2^64]phi(P)] in that same order; flattening alone
// does not check a trusted provider's bases or its bias correction.
pub fn flatten_chunks<let N: u32>(chunks: [[Field; 2]; 2 * N]) -> [Field; 4 * N] {
    let mut out = [0; 4 * N];
    for i in 0..2 * N {
        out[2 * i] = chunks[i][0];
        out[2 * i + 1] = chunks[i][1];
    }
    out
}

/// Untrusted hint; callers must retain check_glv_and_chunks before using output.
pub unconstrained fn split_chunks<let N: u32>(components: [[Field; 2]; N]) -> [[Field; 2]; 2 * N] {
    let mut out = [[0; 2]; 2 * N];
    for i in 0..N {
        for j in 0..2 {
            let v = components[i][j] as u128;
            out[2 * i + j] = [(v & 18446744073709551615) as Field, (v >> 64) as Field];
        }
    }
    out
}

mod tests {
    use super::{BIAS, check_glv_and_chunks, flatten_chunks, split_chunks};

    // s = (u - BIAS) + LAMBDA * (v - BIAS) holds for u = BIAS + s, v = BIAS.
    #[test]
    fn accepts_biased_decomposition_and_recomposed_chunks() {
        let components = [[BIAS + 5, BIAS], [BIAS, BIAS]];
        // Safety: test-only hint; check_glv_and_chunks constrains it below.
        let chunks = unsafe { split_chunks(components) };
        check_glv_and_chunks([5, 0], components, chunks);
        // BIAS = 2^126 splits into a zero low chunk and 2^62.
        assert(chunks[1] == [0, 4611686018427387904]);
        assert(chunks[0] == [5, 4611686018427387904]);
        let hi = 4611686018427387904;
        assert(flatten_chunks::<2>(chunks) == [5, hi, 0, hi, 0, hi, 0, hi]);
    }

    #[test(should_fail_with = "Invalid GLV decomposition")]
    fn rejects_components_of_another_scalar() {
        let components = [[BIAS + 5, BIAS]];
        // Safety: test-only hint.
        let chunks = unsafe { split_chunks(components) };
        check_glv_and_chunks([6], components, chunks);
    }

    #[test(should_fail_with = "Invalid fixed-base chunk recomposition")]
    fn rejects_chunks_of_another_component() {
        let components = [[BIAS + 5, BIAS]];
        check_glv_and_chunks(
            [5],
            components,
            [[4, 4611686018427387904], [0, 4611686018427387904]],
        );
    }
}
