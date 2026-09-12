use std::{error::Error as StdError, fmt};

use crate::{blockchain::BlockError, consensus::EmissionError};

#[derive(Debug)]
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
    Serialization,
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlock(error) => write!(f, "invalid block: {error}"),
            Self::InvalidEmission(error) => write!(f, "invalid emission: {error}"),
            Self::InvalidDifficulty => f.write_str("difficulty is outside allowed range"),
            Self::UnexpectedDifficulty => {
                f.write_str("block difficulty does not match expected difficulty")
            }
            Self::InvalidPoWParameters => f.write_str("proof-of-work parameters are invalid"),
            Self::PoWHashFailed => f.write_str("proof-of-work hash failed"),
            Self::InvalidHeight => f.write_str("block height does not extend tip"),
            Self::InvalidPreviousHash => f.write_str("block previous hash does not match tip"),
            Self::GenesisRequired => {
                f.write_str("canonical chain must be initialized through validated genesis")
            }
            Self::WrongGenesis => {
                f.write_str("genesis block does not match configured chain identity")
            }
            Self::InsufficientPoW => {
                f.write_str("block hash does not satisfy proof-of-work difficulty")
            }
            Self::Serialization => f.write_str("consensus encoding failed"),
        }
    }
}

impl StdError for ConsensusError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidEmission(error) => Some(error),
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
