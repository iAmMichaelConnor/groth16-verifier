//! Constrained building blocks for hinted BN254 pairing-product checks: the
//! polynomial representation of Fq12, line evaluations, the Fiat-Shamir
//! transcript and the 68-identity certificate relations (after Novakovic and
//! Eagen, "On Proving Pairings", https://eprint.iacr.org/2024/640).
//!
//! These helpers alone do not verify a Groth16 proof: a pairing-product check
//! without the public-input binding is forgeable. Use `groth16::verify` or
//! `runtime_verifier::verify`. docs/OPTIMISATIONS.md gives the equations.
pub mod polynomial;
pub mod lines;
pub mod transcript;

pub mod certificate;
