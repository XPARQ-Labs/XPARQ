//! Shared kernel primitives and re-exports of lower-level contracts.
pub use crypto::primitives::{codec, types};

pub mod input;
pub mod output;

pub use codec::{
    CANONICAL_ENCODING_PROFILE, canonical_bytes, canonical_decode, canonical_deserialize,
};
pub use crypto::primitives::CodecError;
pub use crypto::primitives::{HASH_SIZE, domain_hash};
pub use input::Input;
pub use output::Output;
pub use types::{BlockHeight, BlockNonce, Height, Nonce};
