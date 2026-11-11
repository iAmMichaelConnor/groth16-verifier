// Exact injective representation of the preserved trusted offset table.
// Four low+2^120*middle words, then four top14 limbs and correction infinity.
// One bounded index selects all five words; the initial offset is always finite.
use super::fixed_key_glv::Half;
use bigcurve::{BigCurve, ScalarField};
use bignum::{BigNum, BN254_Fq as Fp};

pub use fixed_g1_helpers::offset_codec::unpack_hint;

fn from_decoded(values: [Fp; 4], flag: bool) -> (Half, Half) {
    (
        Half { x: values[0], y: values[1], is_infinity: false },
        Half { x: values[2], y: values[3], is_infinity: flag },
    )
}

pub fn select<let C: u32>(table: [[Field; 5]; C], index: u32) -> (Half, Half) {
    let (values, flag) = fixed_g1_helpers::offset_codec::select(table, index);
    from_decoded(values, flag)
}

pub unconstrained fn find_index<let S: u32, let M: u32, let C: u32>(
    points: [Half; M],
    scalars: [ScalarField<S>; M],
    table: [[Field; 5]; C],
) -> u32 {
    let mut origins = [Half::point_at_infinity(); C];
    for i in 0..C {
        let (raw, _) = unpack_hint(table[i]);
        origins[i] =
            Half { x: Fp::from_limbs(raw[0]), y: Fp::from_limbs(raw[1]), is_infinity: false };
    }
    bigcurve::internal::find_safe_msm_offset::<Fp, Half, S, M, C>(points, scalars, origins)
}
