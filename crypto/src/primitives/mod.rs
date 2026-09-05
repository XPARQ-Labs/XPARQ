//! Shared canonical encoding, hashing, and scalar types used below the kernel.
pub mod codec;
mod error;
mod hash;
pub mod types;
pub use codec::{
    CANONICAL_ENCODING_PROFILE, canonical_bytes, canonical_decode, canonical_deserialize,
};
pub use error::CodecError;
pub use hash::{HASH_SIZE, domain_hash};
pub use types::{BlockHeight, BlockNonce, Height, Nonce};
