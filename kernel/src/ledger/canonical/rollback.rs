//! Rollback journal retention and atomic tip rollback.

use super::{Ledger, LedgerError};
use crate::{blockchain::Block, common::Height};
use crypto::StateRoot;

impl Ledger {
    /// Whether the shallow rollback fast path has all journals after this height.
    pub fn can_rollback_to(&self, ancestor: Height) -> bool {
        self.chain
            .headers()
            .rev()
            .take_while(|(height, _)| **height > ancestor)
            .all(|(height, _)| self.journals.contains_key(height))
    }

    /// Local undo metadata only; callers must retain a recovery path and receipts.
    pub fn prune_rollback_journals_before(&mut self, height: Height) {
        let height = self.tip_height().map_or(height, |tip| height.min(tip));
        self.journals.retain(|key, _| *key >= height);
    }

    pub fn rollback_journal_heights(&self) -> impl Iterator<Item = Height> + '_ {
        self.journals.keys().copied()
    }

    /// Test-only simulation of an expired local rollback journal.
    #[cfg(feature = "devnet")]
    pub fn discard_rollback_journals_before(&mut self, height: Height) {
        self.journals.retain(|key, _| *key >= height);
    }

    pub fn rollback_tip(&mut self) -> Result<Block, LedgerError> {
        let height = self.chain.tip_height().ok_or(LedgerError::EmptyChain)?;

        let hash = self.chain.tip_hash().ok_or(LedgerError::EmptyChain)?;

        let tip = self.chain.block(&height).ok_or(LedgerError::EmptyChain)?;

        if self.state_root()? != tip.state_root() {
            return Err(LedgerError::InvalidPriorStateRoot);
        }

        let journals = self
            .journals
            .get(&height)
            .cloned()
            .ok_or(LedgerError::MissingRollbackJournal)?;

        let mut staged_state = self.state.clone();

        for journal in journals.into_iter().rev() {
            staged_state.rollback_state(journal)?;
        }

        let mut staged_chain = self.chain.clone();

        let block = staged_chain.remove_tip(hash)?;

        staged_state.validate_supply_invariants()?;

        let expected_root = match staged_chain.tip_height() {
            Some(parent_height) => {
                staged_chain
                    .header(&parent_height)
                    .ok_or(LedgerError::EmptyChain)?
                    .state_root
            }

            None => StateRoot::ZERO,
        };

        if staged_state.application_state_root()? != expected_root {
            return Err(LedgerError::InvalidRollbackStateRoot);
        }

        self.state = staged_state;

        self.chain = staged_chain;

        self.journals.remove(&height);

        if self.chain.tip_height().is_none() {
            self.chain_context = None;
        }

        Ok(block)
    }
}
