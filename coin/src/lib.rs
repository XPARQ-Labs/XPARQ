//! Fundamental XPQ coin value types.
//!
//! This crate deliberately contains no transaction, ledger, consensus, or
//! wallet-file behavior.

mod coin;
mod error;

pub use coin::*;
pub use error::CoinIdParseError;
