//! Public types for application-local, trusted FixedKey implementations.
//!
//! Generate these implementations from an authenticated verification key. The
//! trait does not constrain arbitrary preprocessing supplied by its implementer.
//! Every alias below is the exact type used by the verifier, not a conversion.
pub use crate::optimized::fixed_key::FixedKey;
pub use crate::optimized::fixed_key_glv::Half;
pub use crate::optimized::offset_protocol::OFFSET_FACTOR;
pub use crate::types::{Proof, VerifyingKey};
pub use fields::{BigNum, fp12::Fp12, fp2::Fp2, fp6::Fp6, fp::Fp};
pub use g1::g1::G1Affine;
pub use g2::g2::{G2Affine, LineEvaluation, LineScheduleRaw};
