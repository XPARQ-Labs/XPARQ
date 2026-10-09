//! Ledger-owned unspent coin outputs and asset shares.
//!
//! Both stores live here while keeping their canonical encodings and checked
//! monetary rules separate. Asset metadata types remain in `monetary::asset`.

pub mod asset;
mod coin;

pub use crate::monetary::asset::AssetShare;
pub(crate) use asset::ExecutionContext;
pub use asset::{AssetJournal, AssetState};
pub use coin::{CoinUtxo, Error, UtxoSet};
