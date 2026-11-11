//! SP1 v5 Groth16 proofs: the pinned SP1 v5 verification key as a
//! `groth16::FixedKey` (`Sp1Key`) and the public-input mapping
//! (`sp1_public_inputs`). Verify with `groth16::verify::<Sp1Key, 2>`.
//!
//! SP1 v6 Groth16 proofs: the `v6` module, with its complete entry point
//! `v6::verify`.
//!
//! A valid proof says only that some SP1 program with the given program key
//! produced the given public values. The application must authorise the
//! program key and interpret the public values.
pub(crate) mod generated;
mod key;
pub mod inputs;
pub use inputs::{hash_to_field, sp1_public_inputs};
pub use key::Sp1Key;
pub mod v6;
mod benchmarks;
