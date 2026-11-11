//! Fixed-key Groth16 verification for BN254 (Circom/snarkjs keys and proofs).
//!
//! The verification key is compiled in: an application module implements
//! [`FixedKey`] with key material generated from an authenticated verification
//! key (see the repository README). [`verify`] checks a proof against public
//! inputs with every constraint in the circuit and works on any Noir backend.
//!
//! Helpers that check only part of a Groth16 statement are not exported: a
//! pairing-product check without the public-input binding is forgeable.
pub(crate) mod types;

pub(crate) mod optimized;

/// Types for application-local, trusted `FixedKey` implementations.
pub mod provider;
pub use optimized::fixed_verifier::verify;
pub use provider::FixedKey;
