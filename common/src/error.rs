use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    EncodeFailed,
    DecodeFailed,
    InvalidTransaction,
    InvalidBlock,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodeFailed => f.write_str("canonical value could not be encoded"),
            Self::DecodeFailed => f.write_str("canonical bytes could not be decoded"),
            Self::InvalidTransaction => f.write_str("decoded transaction is invalid"),
            Self::InvalidBlock => f.write_str("decoded block is invalid"),
        }
    }
}

impl Error for CodecError {}
