//! Ledger validation and transition errors.

use crate::{
    blockchain::ChainError,
    consensus::{ConsensusError, DeployConsensusError, EmissionError, ProgramConsensusError},
    ledger::StateError,
};
use std::{error::Error as StdError, fmt};

#[derive(Debug)]

pub enum LedgerError {
    Consensus(ConsensusError),

    ProgramCall(ProgramConsensusError),
    Deploy(DeployConsensusError),

    State(StateError),

    Chain(ChainError),

    Emission(EmissionError),

    EmptyChain,

    MissingRollbackJournal,

    InvalidStateRoot,

    InvalidPriorStateRoot,

    InvalidRollbackStateRoot,

    InvalidBlockWeight,

    SupplyOverflow,

    CoinSupplyMismatch,

    InvalidCoinState,

    InvalidAssetState,

    InvalidProgramState,

    BlockAccountingMismatch,

    AssetSupplyMismatch,

    UnknownAssetShare,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(error) => {
                write!(formatter, "consensus validation failed: {error}")
            }

            Self::ProgramCall(error) => {
                write!(formatter, "operation validation failed: {error}")
            }
            Self::Deploy(error) => write!(formatter, "deploy validation failed: {error:?}"),

            Self::State(error) => {
                write!(formatter, "ledger state transition failed: {error}")
            }

            Self::Chain(error) => {
                write!(formatter, "chain transition failed: {error}")
            }

            Self::Emission(error) => {
                write!(formatter, "emission validation failed: {error}")
            }

            Self::EmptyChain => formatter.write_str("ledger chain is empty"),

            Self::MissingRollbackJournal => formatter.write_str("rollback journal is missing"),

            Self::InvalidStateRoot => formatter.write_str("block state root does not match ledger"),

            Self::InvalidPriorStateRoot => {
                formatter.write_str("active state root does not match canonical tip")
            }

            Self::InvalidRollbackStateRoot => {
                formatter.write_str("rolled-back state root does not match parent block")
            }

            Self::InvalidBlockWeight => {
                formatter.write_str("block execution weight does not match ledger")
            }

            Self::SupplyOverflow => formatter.write_str("UTXO supply sum overflowed"),

            Self::CoinSupplyMismatch => {
                formatter.write_str("coin UTXO total does not match supply")
            }

            Self::InvalidCoinState => formatter.write_str("coin state contains a zero-value UTXO"),

            Self::InvalidProgramState => formatter.write_str("invalid program registry state"),
            Self::InvalidAssetState => {
                formatter.write_str("asset state contains invalid metadata or a zero-value share")
            }

            Self::BlockAccountingMismatch => {
                formatter.write_str("block coin supply delta does not match subsidy and burns")
            }

            Self::AssetSupplyMismatch => {
                formatter.write_str("asset share total does not match recorded supply")
            }

            Self::UnknownAssetShare => formatter.write_str("asset share has no registered asset"),
        }
    }
}

impl StdError for LedgerError {}

impl From<ConsensusError> for LedgerError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<ProgramConsensusError> for LedgerError {
    fn from(error: ProgramConsensusError) -> Self {
        Self::ProgramCall(error)
    }
}

impl From<DeployConsensusError> for LedgerError {
    fn from(error: DeployConsensusError) -> Self {
        Self::Deploy(error)
    }
}

impl From<EmissionError> for LedgerError {
    fn from(error: EmissionError) -> Self {
        Self::Emission(error)
    }
}

impl From<StateError> for LedgerError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<crate::ledger::utxo::Error> for LedgerError {
    fn from(error: crate::ledger::utxo::Error) -> Self {
        Self::State(StateError::Utxo(error))
    }
}

impl From<ChainError> for LedgerError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<crypto::CodecError> for LedgerError {
    fn from(_error: crypto::CodecError) -> Self {
        Self::Consensus(ConsensusError::Serialization)
    }
}
