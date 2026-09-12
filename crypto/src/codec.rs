//! Canonical wire encoding shared by the protocol crates.

use borsh::{
    BorshDeserialize,
    BorshSerialize,
};
use std::{
    error::Error,
    fmt,
};

pub const CANONICAL_ENCODING_PROFILE: &str = "xparq-borsh-le";

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
pub enum CodecError {
    EncodeFailed,
    DecodeFailed,
    InvalidTransaction,
    InvalidBlock,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodeFailed => formatter.write_str("canonical value could not be encoded"),
            Self::DecodeFailed => formatter.write_str("canonical bytes could not be decoded"),
            Self::InvalidTransaction => formatter.write_str("decoded transaction is invalid"),
            Self::InvalidBlock => formatter.write_str("decoded block is invalid"),
        }
    }
}

impl Error for CodecError {}

pub fn canonical_bytes<T: BorshSerialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    borsh::to_vec(value).map_err(|_| CodecError::EncodeFailed)
}

pub fn canonical_deserialize<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    T::try_from_slice(bytes).map_err(|_| CodecError::DecodeFailed)
}

pub fn canonical_decode<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    canonical_deserialize(bytes)
}
