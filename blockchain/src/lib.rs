pub mod block;
pub mod chain;
pub mod codec;
mod error;

pub use block::*;
pub use chain::Chain;
pub use codec::{block_bytes, block_header_bytes, block_header_hash, decode_block};
pub use error::{BlockError, ChainError};

pub(crate) mod crypto {
    pub use xparq_crypto::*;
}

pub(crate) mod transaction {
    pub use xparq_transaction::*;
}
