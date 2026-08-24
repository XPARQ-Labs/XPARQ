use crate::EmissionError;
use crate::block::BlockError;
use std::{error::Error, fmt};
pub use xparq_common::CodecError;
pub use xparq_crypto::CryptoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusError {
    InvalidBlock(BlockError),
    InvalidEmission(EmissionError),
    InvalidDifficulty,
    UnexpectedDifficulty,
    InvalidPoWParameters,
    PoWHashFailed,
    InvalidHeight,
    InvalidPreviousHash,
    GenesisRequired,
    WrongGenesis,
    InsufficientPoW,
    Serialization(CodecError),
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusError::InvalidBlock(error) => write!(f, "invalid block: {error}"),
            ConsensusError::InvalidEmission(error) => write!(f, "invalid emission: {error}"),
            ConsensusError::InvalidDifficulty => f.write_str("difficulty is outside allowed range"),
            ConsensusError::UnexpectedDifficulty => {
                f.write_str("block difficulty does not match expected difficulty")
            }
            ConsensusError::InvalidPoWParameters => {
                f.write_str("proof-of-work parameters are invalid")
            }
            ConsensusError::PoWHashFailed => f.write_str("proof-of-work hash failed"),
            ConsensusError::InvalidHeight => f.write_str("block height does not extend tip"),
            ConsensusError::InvalidPreviousHash => {
                f.write_str("block previous hash does not match tip")
            }
            ConsensusError::GenesisRequired => {
                f.write_str("canonical chain must be initialized through validated genesis")
            }
            ConsensusError::WrongGenesis => {
                f.write_str("genesis block does not match configured chain identity")
            }
            ConsensusError::InsufficientPoW => {
                f.write_str("block hash does not satisfy proof-of-work difficulty")
            }
            ConsensusError::Serialization(error) => write!(f, "consensus encoding failed: {error}"),
        }
    }
}

impl Error for ConsensusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidEmission(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EmissionError> for ConsensusError {
    fn from(error: EmissionError) -> Self {
        Self::InvalidEmission(error)
    }
}

impl From<BlockError> for ConsensusError {
    fn from(error: BlockError) -> Self {
        Self::InvalidBlock(error)
    }
}

impl From<CodecError> for ConsensusError {
    fn from(error: CodecError) -> Self {
        Self::Serialization(error)
    }
}
