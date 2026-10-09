pub mod agility;
pub mod argon2;
pub mod codec;
mod error;
pub mod hash;
pub mod mldsa;
pub mod program_id;
pub mod signature;
pub mod slhdsa;

pub mod crypto {
    pub use crate::*;
}

pub use agility::*;
pub use argon2::*;
pub use codec::{
    CANONICAL_ENCODING_PROFILE, CodecError, canonical_bytes, canonical_decode,
    canonical_deserialize, canonical_fixed_map_length, canonical_length,
};
pub use error::CryptoError;
pub use hash::*;
pub use program_id::*;
pub use signature::*;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct ChainContext {
    pub genesis_hash: [u8; crate::HASH_SIZE],
}

impl ChainContext {
    pub const fn new(genesis_hash: [u8; crate::HASH_SIZE]) -> Self {
        Self { genesis_hash }
    }
}
