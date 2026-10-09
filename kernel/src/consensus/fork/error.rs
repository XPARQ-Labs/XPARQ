use std::{error::Error, fmt};
#[derive(Debug)]
pub enum ForkChoiceError {
    DuplicateBlock,
    UnexpectedGenesis,
    InvalidBlock(crate::blockchain::BlockError),
    InvalidDifficulty,
    InvalidHeader,
    InvalidProofOfWork(crate::consensus::ConsensusError),
    InvalidHeight,
    MissingParent,
    Serialization,
}

impl fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBlock => f.write_str("block already exists in fork graph"),
            Self::UnexpectedGenesis => {
                f.write_str("fork graph genesis does not match the configured chain")
            }
            Self::InvalidBlock(error) => write!(f, "fork graph block is invalid: {error}"),
            Self::InvalidDifficulty => f.write_str("block difficulty is invalid for its branch"),
            Self::InvalidHeader => f.write_str("block header fields are outside consensus bounds"),
            Self::InvalidProofOfWork(error) => write!(f, "block proof of work is invalid: {error}"),
            Self::InvalidHeight => f.write_str("block height does not follow its parent"),
            Self::MissingParent => f.write_str("block parent is missing from fork graph"),
            Self::Serialization => f.write_str("fork graph encoding failed"),
        }
    }
}

impl Error for ForkChoiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidProofOfWork(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgError {
    InvalidBranch,
}

impl fmt::Display for ReorgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBranch => f.write_str("reorganization branch is incomplete or invalid"),
        }
    }
}

impl Error for ReorgError {}
