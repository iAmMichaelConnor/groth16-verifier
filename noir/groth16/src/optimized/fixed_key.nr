//! Compile-time trusted preprocessing providers. These are code, never witness inputs.
//! Implementations must be generated/reviewed from one authenticated verification key.
//! The trait alone cannot certify arbitrary hand-written preprocessing consistency.
use crate::types::VerifyingKey;
use super::fixed_key_glv::Half;
use super::offset_protocol::OFFSET_FACTOR;
use fields::fp12::Fp12;
use g2::g2::LineScheduleRaw;

pub trait FixedKey<let N: u32> {
    // Reference data: the verifier never reads it. It keeps the verification key
    // that the other methods were derived from next to them, for review and for
    // the consistency checks in scripts/tests.
    fn verification_key() -> VerifyingKey<N + 1>;
    fn msm_points() -> [Half; 4 * N];
    fn msm_correction() -> Half;
    fn msm_correction_including_offset() -> Half;
    fn msm_offset_pairs() -> [[Field; 5]; OFFSET_FACTOR * N + 1];
    fn gamma_lines() -> LineScheduleRaw;
    fn delta_lines() -> LineScheduleRaw;
    fn t_preimage() -> Fp12;
}
