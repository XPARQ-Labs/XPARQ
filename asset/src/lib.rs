mod error;
mod identifier;
mod program;

pub use error::AssetIdParseError;
pub use program::*;

#[path = "bitcoin/bitcoin.rs"]
pub mod bitcoin;
#[path = "ethereum/ethereum.rs"]
pub mod ethereum;
#[path = "solana/solana.rs"]
pub mod solana;
