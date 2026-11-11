use bigcurve::{BigCurve, BigCurveParams, BN254, derive_curve_impl, ScalarField};
use bignum::{BigNum, BN254_Fq as Fp};
// Same BN254 curve and initial offset. Only the scalar-window count changes.
global PARAMS: BigCurveParams<Fp> = BigCurveParams {
    a: Fp::zero(),
    b: Fp::from(3),
    one: [Fp::from_limbs([1, 0, 0]), Fp::from_limbs([2, 0, 0])],
    offset_generator: [
        Fp::from_limbs([
            806912518130241167103403008989836859,
            1098072398138531243883566670229416825,
            11186,
        ]),
        Fp::from_limbs([
            733513013818297462602632056469156242,
            136482665324975917551620587501661440,
            9340,
        ]),
    ],
    offset_generator_final: [
        Fp::from_limbs([
            984614817937368149819875460813102985,
            892221540872754015941009085801273575,
            6258,
        ]),
        Fp::from_limbs([
            1259428831050327544522354068744942249,
            1302022545135632074528816954694042827,
            54,
        ]),
    ],
};
#[derive_curve_impl(quote { Fp }, quote { PARAMS })]
pub struct Half {
    pub x: Fp,
    pub y: Fp,
    pub is_infinity: bool,
}

use super::fixed_key::FixedKey;
use super::offset_pairs;
use super::offset_protocol::{BASES_PER_INPUT, OFFSET_FACTOR, WINDOWS};

// Accepted relation: L=IC0+sum_i [inputs[i]]IC_(i+1). For ordinary finite
// bases, K=IC0-[2^126]sum_i(P_i+phi(P_i)); each trusted selected row uses
// C_j=K-[2^60]O_j. The MSM contributes [2^60]O_j, so final addition
// cancels the SAME selected origin. Infinity IC slots follow the provider's
// existing dummy-base/zero-scalar rule, not incomplete arithmetic on infinity.
// N=0 returns the trusted correction directly; callers apply their final
// finite-point policy. No uniqueness of the bounded GLV decomposition is needed.
fn glv_fixed_with_chunks<Key, let N: u32>(
    inputs: [Field; N],
    components: [[Field; 2]; N],
    chunks: [[Field; 2]; 2 * N],
) -> BN254
where
    Key: FixedKey<N>,
{
    fixed_g1_helpers::scalar::check_glv_and_chunks::<N>(inputs, components, chunks);
    let correction = Key::msm_correction();
    if N == 0 {
        BN254 { x: correction.x, y: correction.y, is_infinity: correction.is_infinity }
    } else {
        let scalars: [ScalarField<16>; 4 * N] = fixed_g1_helpers::scalar::flatten_chunks::<N>(
            chunks,
        )
            .map(|value| ScalarField::from(value));
        let points = Key::msm_points();
        let table = Key::msm_offset_pairs();
        // Safety: index only chooses trusted matched constants. Bounds, decoding and
        // every arithmetic step remain constrained, independent of selector behavior.
        let selected = unsafe {
            offset_pairs::find_index::<WINDOWS, BASES_PER_INPUT * N, OFFSET_FACTOR * N + 1>(
                points,
                scalars,
                table,
            )
        };
        let (origin, correction) = offset_pairs::select(table, selected);
        let out = bigcurve::internal::evaluate_linear_expression_preserving_selected_offset::<Fp, Half, 16, 4 * N, 1>(
            points,
            scalars,
            [correction],
            origin,
        );
        BN254 { x: out.x, y: out.y, is_infinity: out.is_infinity }
    }
}

pub unconstrained fn split_chunks<let N: u32>(components: [[Field; 2]; N]) -> [[Field; 2]; 2 * N] {
    fixed_g1_helpers::scalar::split_chunks::<N>(components)
}

pub fn glv_fixed<Key, let N: u32>(inputs: [Field; N], components: [[Field; 2]; N]) -> BN254
where
    Key: FixedKey<N>,
{
    // Safety: every hinted chunk is range checked and exactly recomposed above.
    let chunks = unsafe { split_chunks(components) };
    glv_fixed_with_chunks::<Key, N>(inputs, components, chunks)
}
