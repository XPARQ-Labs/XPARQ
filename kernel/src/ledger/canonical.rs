//! Canonical ledger API; implementation modules own each transition responsibility.

use std::collections::BTreeMap;

use borsh::BorshSerialize;
use crypto::{BlockHash, StateRoot};

use crate::{
    blockchain::{Block, Chain},
    common::Height,
    ledger::{LedgerState, StateRollbackJournal},
    monetary::coin::Zeno,
};

#[path = "canonical/accounting.rs"]
mod accounting;
#[path = "canonical/error.rs"]
mod error;
#[path = "canonical/execution.rs"]
mod execution;
#[path = "canonical/rollback.rs"]
mod rollback;
#[path = "canonical/snapshot.rs"]
mod snapshot;
#[path = "canonical/state_root.rs"]
mod state_root;
#[path = "canonical/state_view.rs"]
mod state_view;

pub use error::LedgerError;
pub use snapshot::{LedgerSnapshot, SnapshotRestoreMetrics};

/// Live ledger state is changed through validated application and restoration.
/// Read access does not grant permission to replace the monetary state.
///
/// ```compile_fail
/// use kernel::ledger::{Ledger, LedgerState};
/// let mut ledger = Ledger::new();
/// ledger.state = LedgerState::default();
/// ```
///
/// Raw ledger bytes are not a validated restore path. Decode a `LedgerSnapshot`
/// and restore it against the appropriate locally validated block history.
///
/// ```compile_fail
/// use borsh::BorshDeserialize;
/// use kernel::ledger::Ledger;
/// let _ = Ledger::try_from_slice(&[]);
/// ```
#[derive(BorshSerialize, Clone, Debug, Default)]
pub struct Ledger {
    #[borsh(skip)]
    applications: crate::program::application::Applications,

    pub chain: Chain,

    pub(crate) state: LedgerState,

    journals: BTreeMap<Height, Vec<StateRollbackJournal>>,

    chain_context: Option<crate::common::ChainContext>,
}

impl PartialEq for Ledger {
    fn eq(&self, other: &Self) -> bool {
        self.chain == other.chain
            && self.state == other.state
            && self.journals == other.journals
            && self.chain_context == other.chain_context
    }
}
impl Eq for Ledger {}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the protocol application set before preview, mining, or replay.
    pub fn with_applications(
        mut self,
        executor: impl crate::program::application::ApplicationExecutor + 'static,
    ) -> Self {
        self.applications = crate::program::application::Applications::new(executor);
        self
    }

    pub fn tip_height(&self) -> Option<Height> {
        self.chain.tip_height()
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.chain.tip_hash()
    }

    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    pub fn state_root(&self) -> Result<StateRoot, LedgerError> {
        self.state.application_state_root()
    }

    pub fn program_call_protocol_burns(
        &self,

        height: Height,
    ) -> Option<Vec<crate::monetary::coin::Zeno>> {
        let block = self.chain.block(&height)?;

        self.program_call_protocol_burns_for_block(block)
    }

    /// Read receipts for a verified historical body supplied by a node store.
    pub fn program_call_protocol_burns_for_block(&self, block: &Block) -> Option<Vec<Zeno>> {
        if self.chain.header(&block.height()) != Some(&block.header) {
            return None;
        }
        let journals = self.journals.get(&block.height())?;

        let offset = usize::from(block.emission().is_some());

        let operation_journals = journals.get(offset..)?;

        if operation_journals.len() != block.operations().len() {
            return None;
        }

        Some(
            operation_journals
                .iter()
                .map(StateRollbackJournal::protocol_burn)
                .collect(),
        )
    }
}

#[cfg(all(test, feature = "mainnet"))]
#[path = "phase4_vectors.rs"]
mod phase4_vectors;

#[cfg(test)]
#[path = "canonical/tests.rs"]
mod p3e_block_atomicity_tests;
