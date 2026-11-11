//! The runtime pairing adapter's G1 coordinate type, with no curve operations.
//! Kept apart from the public `g1` package so the runtime-key dependency graph
//! does not pull in the fixed-key BigCurve fork.
pub use fields::fp;
pub mod g1;
