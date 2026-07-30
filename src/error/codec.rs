use std::error::Error;
use std::fmt;

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
            CodecError::EncodeFailed => f.write_str("canonical value could not be encoded"),
            CodecError::DecodeFailed => f.write_str("canonical bytes could not be decoded"),
            CodecError::InvalidTransaction => f.write_str("decoded transaction is invalid"),
            CodecError::InvalidBlock => f.write_str("decoded block is invalid"),
        }
    }
}

impl Error for CodecError {}
