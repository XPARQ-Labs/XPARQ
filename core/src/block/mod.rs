#![allow(clippy::module_inception)]

mod block;
pub mod merkle;

pub use block::*;

// Stable names shared by the node and wallet crates.
pub type BlockHeader = Header;
pub type BlockBody = Body;
pub type CoinbaseTransaction = EmissionTransaction;
