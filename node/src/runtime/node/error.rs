use crate::runtime::mempool::MempoolError;
use crate::runtime::storage::StorageError;
use std::error::Error;
use std::fmt;
use xparq::consensus::ConsensusError;
use xparq::genesis::GenesisError;
use xparq::ledger::LedgerError;
use xparq::ledger::fork_choice::ForkChoiceError;

#[derive(Debug)]
pub enum NodeError {
    Consensus(ConsensusError),
    Genesis(GenesisError),
    ForkChoice(ForkChoiceError),
    Ledger(LedgerError),
    Mempool(MempoolError),
    Storage(StorageError),
    Codec(xparq::error::CodecError),
    MissingGenesisState,
    MissingStagedLedger,
    MissingBestTip,
    MissingCommonAncestor,
    MissingForkBranch,
    MissingActiveTip,
    MissingForkNode,
    MissingDifficultyAnchor,
    TransactionIndexOverflow,
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Consensus(error) => write!(f, "consensus error: {error}"),
            NodeError::Genesis(error) => write!(f, "genesis error: {error}"),
            NodeError::ForkChoice(error) => write!(f, "fork choice error: {error}"),
            NodeError::Ledger(error) => write!(f, "ledger error: {error}"),
            NodeError::Mempool(error) => write!(f, "mempool error: {error}"),
            NodeError::Storage(error) => write!(f, "storage error: {error}"),
            NodeError::Codec(error) => write!(f, "canonical encoding error: {error}"),
            NodeError::MissingGenesisState => {
                f.write_str("node cannot reorg without the genesis account state")
            }
            NodeError::MissingStagedLedger => {
                f.write_str("validated active-tip block is missing its staged ledger")
            }
            NodeError::MissingBestTip => f.write_str("fork graph has no selected best tip"),
            NodeError::MissingCommonAncestor => {
                f.write_str("fork branches do not have a known common ancestor")
            }
            NodeError::MissingForkBranch => {
                f.write_str("fork graph cannot construct the requested branch")
            }
            NodeError::MissingActiveTip => f.write_str("active ledger tip is missing"),
            NodeError::MissingForkNode => f.write_str("required block is missing from fork graph"),
            NodeError::MissingDifficultyAnchor => {
                f.write_str("WBDA difficulty weight anchor is missing")
            }
            NodeError::TransactionIndexOverflow => {
                f.write_str("block transaction index exceeds supported range")
            }
        }
    }
}

impl Error for NodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NodeError::Consensus(error) => Some(error),
            NodeError::Genesis(error) => Some(error),
            NodeError::ForkChoice(error) => Some(error),
            NodeError::Ledger(error) => Some(error),
            NodeError::Mempool(error) => Some(error),
            NodeError::Storage(error) => Some(error),
            NodeError::Codec(error) => Some(error),
            NodeError::MissingGenesisState => None,
            NodeError::MissingStagedLedger
            | NodeError::MissingBestTip
            | NodeError::MissingCommonAncestor
            | NodeError::MissingForkBranch
            | NodeError::MissingActiveTip
            | NodeError::MissingForkNode
            | NodeError::MissingDifficultyAnchor
            | NodeError::TransactionIndexOverflow => None,
        }
    }
}

impl From<ConsensusError> for NodeError {
    fn from(error: ConsensusError) -> Self {
        NodeError::Consensus(error)
    }
}

impl From<GenesisError> for NodeError {
    fn from(error: GenesisError) -> Self {
        NodeError::Genesis(error)
    }
}

impl From<ForkChoiceError> for NodeError {
    fn from(error: ForkChoiceError) -> Self {
        NodeError::ForkChoice(error)
    }
}

impl From<LedgerError> for NodeError {
    fn from(error: LedgerError) -> Self {
        NodeError::Ledger(error)
    }
}

impl From<MempoolError> for NodeError {
    fn from(error: MempoolError) -> Self {
        NodeError::Mempool(error)
    }
}

impl From<StorageError> for NodeError {
    fn from(error: StorageError) -> Self {
        NodeError::Storage(error)
    }
}

impl From<xparq::error::CodecError> for NodeError {
    fn from(error: xparq::error::CodecError) -> Self {
        NodeError::Codec(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_error_exposes_fork_choice_source() {
        let error = NodeError::ForkChoice(ForkChoiceError::Serialization(
            xparq::error::CodecError::InvalidBlock,
        ));
        assert_eq!(
            error.source().unwrap().to_string(),
            "fork graph encoding failed: decoded block is invalid"
        );
        assert_eq!(
            error.source().unwrap().source().unwrap().to_string(),
            "decoded block is invalid"
        );
    }
}
