use std::error::Error;
use std::fmt;
pub use xparq_common::CodecError;

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
            BlockError::MissingEmission => f.write_str("non-genesis block must contain Emission"),
            BlockError::UnexpectedEmission => {
                f.write_str("genesis block must not contain Emission")
            }
            BlockError::BlockTooHeavy => f.write_str("block serialized weight exceeds limit"),
            BlockError::InvalidTransaction => f.write_str("block contains an invalid transaction"),
            BlockError::DuplicateTransaction => {
                f.write_str("block contains a duplicate transaction")
            }
            BlockError::InvalidEmission => f.write_str("block Emission is invalid"),
            BlockError::InvalidMerkleRoot => {
                f.write_str("block merkle root does not match transactions")
            }
            BlockError::InvalidStateRoot => f.write_str("block state root does not match ledger"),
            BlockError::InvalidBlockWeight => {
                f.write_str("block header weight does not match canonical block size")
            }
            BlockError::Serialization(error) => write!(f, "block encoding failed: {error}"),
        }
    }
}

impl Error for BlockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl Error for ChainError {}

impl From<CodecError> for ChainError {
    fn from(error: CodecError) -> Self {
        Self::Serialization(error)
    }
}
