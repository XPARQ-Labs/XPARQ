pub mod codec;
mod error;
pub mod types;

pub use codec::{
    CANONICAL_ENCODING_PROFILE, canonical_bytes, canonical_decode, canonical_deserialize,
};
pub use error::CodecError;
pub use types::{BlockHeight, BlockNonce, Height, Nonce};
