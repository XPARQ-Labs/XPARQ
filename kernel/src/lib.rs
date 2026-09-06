//! XPARQ protocol kernel: canonical types, validation, and state transitions.
//! Networking, persistence, and wallet key management live in application crates.

pub mod asset;
pub mod blockchain;
pub mod coin;
pub mod common;
pub mod consensus;
pub mod genesis;
pub mod ledger;
pub mod transaction;

/// Compatibility path for the public block API.
pub mod block {
    pub use crate::blockchain::*;
}
pub mod codec {
    pub use crate::blockchain::{block_bytes, block_header_bytes, block_header_hash, decode_block};
    pub use crate::common::{canonical_bytes, canonical_decode, canonical_deserialize};
}
pub mod crypto {
    pub use ::crypto::*;
}
