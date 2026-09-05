//! Bridge-facing primitives.
//!
//! This crate defines extension boundaries only. It does not grant bridge code
//! direct access to consensus or ledger mutation.

pub mod source;

pub use source::SourceNetwork;
