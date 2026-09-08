pub mod address;
pub mod agility;
pub mod argon2;
pub mod codec;
mod error;
pub mod falcon;
pub mod hash;
pub mod profile;
pub mod types;

pub mod crypto {
    pub use crate::*;
}

pub use address::*;
pub use agility::*;
pub use argon2::*;
pub use codec::{
    CANONICAL_ENCODING_PROFILE, CodecError, canonical_bytes, canonical_decode,
    canonical_deserialize,
};
pub use error::CryptoError;
pub use falcon::{
    FalconError, FalconKeyPair, FalconLevel, FalconPublicKey, FalconSecretKey, FalconSignature,
    derive_public_key as derive_falcon_public_key, generate_keypair as generate_falcon_keypair,
    keypair_from_seed as falcon_keypair_from_seed, sign as falcon_sign, verify as falcon_verify,
};
pub use hash::*;
pub use profile::*;
pub use types::{BlockHeight, BlockNonce, Height, Nonce};

pub mod block {
    pub use crate::types::{BlockHeight, Height};
}
