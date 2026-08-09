use crate::block::BlockError;
use crate::error::{CodecError, ConsensusError};
use crate::state::{QCashUtxoError, StateError, XpqUtxoError};
use crate::transaction::TransactionError;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    AccountNotFound,
    AccountAlreadyExists,
    InvalidBlock(BlockError),
    InvalidConsensus(ConsensusError),
    InvalidState(StateError),
    InvalidTransaction(TransactionError),
    InvalidSignature,
    InsufficientBalance,
    InvalidStateRoot,
    InvalidEmission,
    InvalidParent,
    InvalidBlockHeight,
    InvalidPreviousHash,
    FinalityViolation,
    DuplicateBlock,
    SupplyOverflow,
    SupplyMismatch,
    UnauthorizedSupplyCreation,
    InvalidQCashUtxo(QCashUtxoError),
    InvalidXpqUtxo(XpqUtxoError),
    MissingQCashAccountJournal,
    EventInvariantViolation,
    Serialization(CodecError),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::AccountNotFound => f.write_str("account was not found"),
            LedgerError::AccountAlreadyExists => f.write_str("account already exists"),
            LedgerError::InvalidBlock(error) => write!(f, "invalid block: {error}"),
            LedgerError::InvalidConsensus(error) => write!(f, "invalid consensus: {error}"),
            LedgerError::InvalidState(error) => write!(f, "invalid state transition: {error}"),
            LedgerError::InvalidTransaction(error) => write!(f, "invalid transaction: {error}"),
            LedgerError::InvalidSignature => f.write_str("transaction signature is invalid"),
            LedgerError::InsufficientBalance => f.write_str("account balance is insufficient"),
            LedgerError::InvalidStateRoot => f.write_str("block state root does not match ledger"),
            LedgerError::InvalidEmission => f.write_str("block Emission is invalid"),
            LedgerError::InvalidParent => f.write_str("block parent does not match ledger tip"),
            LedgerError::InvalidBlockHeight => {
                f.write_str("block height does not extend ledger tip")
            }
            LedgerError::InvalidPreviousHash => {
                f.write_str("block previous hash does not match ledger tip")
            }
            LedgerError::FinalityViolation => {
                f.write_str("reorganization would replace finalized chain history")
            }
            LedgerError::DuplicateBlock => f.write_str("block height already exists in ledger"),
            LedgerError::SupplyOverflow => {
                f.write_str("ledger total supply exceeds maximum supply")
            }
            LedgerError::SupplyMismatch => {
                f.write_str("ledger economic supply does not match authorized issuance")
            }
            LedgerError::UnauthorizedSupplyCreation => {
                f.write_str("only genesis and consensus Emission may create supply")
            }
            LedgerError::InvalidQCashUtxo(error) => {
                write!(f, "invalid QCash UTXO state transition: {error}")
            }
            LedgerError::InvalidXpqUtxo(error) => {
                write!(f, "invalid XPQ UTXO state transition: {error}")
            }
            LedgerError::MissingQCashAccountJournal => {
                f.write_str("QCash account block journal was not found")
            }
            LedgerError::EventInvariantViolation => {
                f.write_str("applied block could not produce canonical protocol events")
            }
            LedgerError::Serialization(error) => write!(f, "ledger encoding failed: {error}"),
        }
    }
}

impl From<QCashUtxoError> for LedgerError {
    fn from(error: QCashUtxoError) -> Self {
        Self::InvalidQCashUtxo(error)
    }
}

impl From<XpqUtxoError> for LedgerError {
    fn from(error: XpqUtxoError) -> Self {
        Self::InvalidXpqUtxo(error)
    }
}

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidConsensus(error) => Some(error),
            Self::InvalidState(error) => Some(error),
            Self::InvalidTransaction(error) => Some(error),
            Self::InvalidQCashUtxo(error) => Some(error),
            Self::InvalidXpqUtxo(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ConsensusError> for LedgerError {
    fn from(error: ConsensusError) -> Self {
        match error {
            ConsensusError::InvalidPreviousHash => Self::InvalidPreviousHash,
            ConsensusError::InvalidHeight => Self::InvalidBlockHeight,
            _ => Self::InvalidConsensus(error),
        }
    }
}

impl From<BlockError> for LedgerError {
    fn from(error: BlockError) -> Self {
        match error {
            BlockError::InvalidStateRoot => Self::InvalidStateRoot,
            BlockError::InvalidEmission | BlockError::MissingEmission => Self::InvalidEmission,
            _ => Self::InvalidBlock(error),
        }
    }
}

impl From<CodecError> for LedgerError {
    fn from(error: CodecError) -> Self {
        Self::Serialization(error)
    }
}

impl From<StateError> for LedgerError {
    fn from(error: StateError) -> Self {
        Self::InvalidState(error)
    }
}

impl From<TransactionError> for LedgerError {
    fn from(error: TransactionError) -> Self {
        match error {
            TransactionError::InvalidSignature
            | TransactionError::InvalidAuthorizationSignature
            | TransactionError::EmptySignature
            | TransactionError::EmptyAuthorizationSignature
            | TransactionError::EmptyPublicKey
            | TransactionError::EmptyAuthorizationPublicKey
            | TransactionError::SenderAddressMismatch => Self::InvalidSignature,
            _ => Self::InvalidTransaction(error),
        }
    }
}
