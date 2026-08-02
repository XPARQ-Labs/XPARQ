use crate::error::CodecError;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    UnsupportedVersion,
    MissingCoinbase,
    UnexpectedCoinbase,
    UnexpectedGenesisAllocation,
    TooManyTransactions,
    BlockTooLarge,
    BlockTooHeavy,
    InvalidTransaction,
    DuplicateTransaction,
    InvalidCoinbase,
    InvalidGenesisAllocation,
    InvalidMerkleRoot,
    InvalidStateRoot,
    InvalidBlockWeight,
    CoinbaseOverflow,
    Serialization(CodecError),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::UnsupportedVersion => f.write_str("block version is unsupported"),
            BlockError::MissingCoinbase => f.write_str("non-genesis block must contain coinbase"),
            BlockError::UnexpectedCoinbase => {
                f.write_str("genesis block must not contain coinbase")
            }
            BlockError::UnexpectedGenesisAllocation => {
                f.write_str("non-genesis block must not contain genesis allocations")
            }
            BlockError::TooManyTransactions => f.write_str("block contains too many transactions"),
            BlockError::BlockTooLarge => f.write_str("block serialized size exceeds limit"),
            BlockError::BlockTooHeavy => f.write_str("block serialized weight exceeds limit"),
            BlockError::InvalidTransaction => f.write_str("block contains an invalid transaction"),
            BlockError::DuplicateTransaction => {
                f.write_str("block contains a duplicate transaction")
            }
            BlockError::InvalidCoinbase => f.write_str("block coinbase is invalid"),
            BlockError::InvalidGenesisAllocation => {
                f.write_str("block genesis allocation is invalid")
            }
            BlockError::InvalidMerkleRoot => {
                f.write_str("block merkle root does not match transactions")
            }
            BlockError::InvalidStateRoot => f.write_str("block state root does not match ledger"),
            BlockError::InvalidBlockWeight => {
                f.write_str("block header weight does not match canonical block size")
            }
            BlockError::CoinbaseOverflow => f.write_str("block coinbase total overflow"),
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
