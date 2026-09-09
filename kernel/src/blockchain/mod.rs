//! Canonical XPARQ block and chain representation.
//!
//! This module owns block encoding, block-local structural validation, Merkle
//! commitments, and the canonical linear chain container. State-dependent
//! Direct transaction validation belongs to `consensus` + `ledger`.

pub mod block;
pub mod chain;
mod error;
pub mod merkle;

pub use block::*;
pub use chain::Chain;
pub use error::{BlockError, ChainError, CodecError};
pub use merkle::{MerkleHash, MerkleInclusionProof};

/// Compatibility namespace for callers such as consensus PoW. The old
/// `codec.rs` file is no longer necessary; these functions live in block.rs.
pub mod codec {
    pub use super::block::{block_bytes, block_header_bytes, block_header_hash, decode_block};
}
