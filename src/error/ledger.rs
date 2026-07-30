use crate::block::BlockError;
use crate::error::{CodecError, ConsensusError};
use crate::state::{QCashUtxoError, StateError, VaultError};
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
    NonceMismatch,
    InvalidStateRoot,
    InvalidCoinbase,
    InvalidParent,
    InvalidBlockHeight,
    InvalidPreviousHash,
    InvalidTimestamp,
    InvalidMedianTimePast,
    FinalityViolation,
    DuplicateBlock,
    SupplyOverflow,
    SupplyMismatch,
    UnauthorizedSupplyCreation,
    InvalidQCashUtxo(QCashUtxoError),
    InvalidVault(VaultError),
    MissingQCashAccountJournal,
    DuplicateGovernanceProposal,
    DuplicateGovernanceProposalFinalization,
    DuplicateGovernanceProposalExecution,
    GovernanceProposalNotAccepted,
    UnknownGovernanceProposal,
    DuplicateGovernanceIssuer,
    UnknownGovernanceIssuer,
    IssuerNotAcceptedForProposal,
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
            LedgerError::NonceMismatch => {
                f.write_str("transaction nonce does not match account nonce")
            }
            LedgerError::InvalidStateRoot => f.write_str("block state root does not match ledger"),
            LedgerError::InvalidCoinbase => f.write_str("block coinbase is invalid"),
            LedgerError::InvalidParent => f.write_str("block parent does not match ledger tip"),
            LedgerError::InvalidBlockHeight => {
                f.write_str("block height does not extend ledger tip")
            }
            LedgerError::InvalidPreviousHash => {
                f.write_str("block previous hash does not match ledger tip")
            }
            LedgerError::InvalidTimestamp => {
                f.write_str("block timestamp must be greater than ledger tip")
            }
            LedgerError::InvalidMedianTimePast => {
                f.write_str("block timestamp must be greater than median time past")
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
                f.write_str("only genesis and consensus coinbase may create supply")
            }
            LedgerError::InvalidQCashUtxo(error) => {
                write!(f, "invalid QCash UTXO state transition: {error}")
            }
            LedgerError::InvalidVault(error) => {
                write!(f, "invalid vault state transition: {error:?}")
            }
            LedgerError::MissingQCashAccountJournal => {
                f.write_str("QCash account block journal was not found")
            }
            LedgerError::DuplicateGovernanceProposal => {
                f.write_str("governance proposal already exists")
            }
            LedgerError::DuplicateGovernanceProposalFinalization => {
                f.write_str("governance proposal is already finalized")
            }
            LedgerError::DuplicateGovernanceProposalExecution => {
                f.write_str("governance proposal is already executed")
            }
            LedgerError::GovernanceProposalNotAccepted => {
                f.write_str("governance proposal is not accepted")
            }
            LedgerError::UnknownGovernanceProposal => {
                f.write_str("governance proposal was not found")
            }
            LedgerError::DuplicateGovernanceIssuer => {
                f.write_str("governance issuer already exists")
            }
            LedgerError::UnknownGovernanceIssuer => f.write_str("governance issuer was not found"),
            LedgerError::IssuerNotAcceptedForProposal => {
                f.write_str("governance credential issuer is not accepted for this proposal")
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

impl Error for LedgerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidConsensus(error) => Some(error),
            Self::InvalidState(error) => Some(error),
            Self::InvalidTransaction(error) => Some(error),
            Self::InvalidQCashUtxo(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ConsensusError> for LedgerError {
    fn from(error: ConsensusError) -> Self {
        match error {
            ConsensusError::InvalidPreviousHash => Self::InvalidPreviousHash,
            ConsensusError::InvalidTimestamp => Self::InvalidTimestamp,
            ConsensusError::InvalidHeight => Self::InvalidBlockHeight,
            _ => Self::InvalidConsensus(error),
        }
    }
}

impl From<BlockError> for LedgerError {
    fn from(error: BlockError) -> Self {
        match error {
            BlockError::InvalidStateRoot => Self::InvalidStateRoot,
            BlockError::InvalidCoinbase | BlockError::MissingCoinbase => Self::InvalidCoinbase,
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
        match error {
            StateError::InsufficientBalance => Self::InsufficientBalance,
            StateError::InvalidNonce => Self::NonceMismatch,
            _ => Self::InvalidState(error),
        }
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
