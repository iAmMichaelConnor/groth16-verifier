use crate::generated::key::Key2;
use groth16::provider::{FixedKey, Fp12, Half, LineScheduleRaw, VerifyingKey};

/// The pinned SP1 v5 Groth16 verification key with its trusted preprocessing.
/// Every method delegates to the generated `Key2`, the single source of the key
/// data; scripts/tests/test_sp1_key.py checks that data against the saved SP1 key.
pub struct Sp1Key {}
impl FixedKey<2> for Sp1Key {
    fn verification_key() -> VerifyingKey<3> {
        Key2::verification_key()
    }
    fn msm_points() -> [Half; 8] {
        Key2::msm_points()
    }
    fn msm_correction() -> Half {
        Key2::msm_correction()
    }
    fn msm_correction_including_offset() -> Half {
        Key2::msm_correction_including_offset()
    }
    fn msm_offset_pairs() -> [[Field; 5]; 273] {
        Key2::msm_offset_pairs()
    }
    fn gamma_lines() -> LineScheduleRaw {
        Key2::gamma_lines()
    }
    fn delta_lines() -> LineScheduleRaw {
        Key2::delta_lines()
    }
    fn t_preimage() -> Fp12 {
        Key2::t_preimage()
    }
}
