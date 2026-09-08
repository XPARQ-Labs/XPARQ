pub use crate::common::CodecError;

use std::{error::Error as StdError, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    MissingEmission,
    UnexpectedEmission,
    BlockTooHeavy,
    InvalidTransaction,
    DuplicateTransaction,
    InvalidEmission,
    InvalidMerkleRoot,
    InvalidStateRoot,
    InvalidBlockWeight,
    Serialization(CodecError),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEmission => f.write_str("non-genesis block must contain emission"),
            Self::UnexpectedEmission => f.write_str("genesis block must not contain emission"),
            Self::BlockTooHeavy => f.write_str("block serialized weight exceeds limit"),
            Self::InvalidTransaction => f.write_str("block contains an invalid transaction"),
            Self::DuplicateTransaction => f.write_str("block contains a duplicate transaction"),
            Self::InvalidEmission => f.write_str("block emission is invalid"),
            Self::InvalidMerkleRoot => f.write_str("block merkle root does not match transactions"),
            Self::InvalidStateRoot => f.write_str("block state root does not match ledger"),
            Self::InvalidBlockWeight => {
                f.write_str("block header weight does not cover canonical block size")
            }
            Self::Serialization(error) => write!(f, "block encoding failed: {error}"),
        }
    }
}

impl StdError for BlockError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodecError> for BlockError {
    fn from(error: CodecError) -> Self {
        Self::Serialization(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    DuplicateBlock,
    InvalidHeight,
    InvalidParent,
    MissingBody,
    Serialization(CodecError),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBlock => f.write_str("block height already exists"),
            Self::InvalidHeight => f.write_str("block height does not extend chain tip"),
            Self::InvalidParent => f.write_str("block parent does not match chain tip"),
            Self::MissingBody => f.write_str("full block body is not retained"),
            Self::Serialization(error) => write!(f, "block encoding failed: {error}"),
        }
    }
}

impl StdError for ChainError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodecError> for ChainError {
    fn from(error: CodecError) -> Self {
        Self::Serialization(error)
    }
}
