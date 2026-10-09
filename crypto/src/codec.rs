//! Canonical wire encoding shared by the protocol crates.

use borsh::{BorshDeserialize, BorshSerialize};
use std::{error::Error, fmt};

pub const CANONICAL_ENCODING_PROFILE: &str = "xparq-borsh-le";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    EncodeFailed,
    DecodeFailed,
    InvalidBlock,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodeFailed => formatter.write_str("canonical value could not be encoded"),
            Self::DecodeFailed => formatter.write_str("canonical bytes could not be decoded"),
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

/// Count canonical bytes without allocating or copying payloads.
pub fn canonical_length<T: BorshSerialize>(value: &T) -> Result<u64, CodecError> {
    struct Counter(u64);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(u64::try_from(bytes.len()).map_err(std::io::Error::other)?)
                .ok_or_else(|| std::io::Error::other("canonical length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    value
        .serialize(&mut counter)
        .map_err(|_| CodecError::EncodeFailed)?;
    Ok(counter.0)
}

/// Borsh map length for an entry type with a constant encoded width.
pub fn canonical_fixed_map_length(entries: usize, entry_bytes: u64) -> Result<u64, CodecError> {
    let count = u32::try_from(entries).map_err(|_| CodecError::EncodeFailed)?;
    u64::from(count)
        .checked_mul(entry_bytes)
        .and_then(|size| size.checked_add(4))
        .ok_or(CodecError::EncodeFailed)
}
