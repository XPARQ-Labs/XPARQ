//! Ledger snapshots and restoration from canonical block history.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use borsh::{BorshDeserialize, BorshSerialize};

use super::{Ledger, LedgerError};
use crate::{
    blockchain::{Block, Chain},
    common::Height,
    consensus::ConsensusError,
    ledger::{LedgerState, StateRollbackJournal},
};

/// Ledger data that cannot be rebuilt from the canonical block log alone.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]

pub struct LedgerSnapshot {
    pub(super) state: LedgerState,

    pub(super) journals: BTreeMap<Height, Vec<StateRollbackJournal>>,
}

/// Wall-clock measurements; excluded from canonical state and snapshot bytes.
#[derive(Debug, Default)]
pub struct SnapshotRestoreMetrics {
    pub history: Duration,
    pub proof_of_work: Duration,
    pub supply_audit: Duration,
    pub registry: Duration,
    pub state_root: Duration,
    pub blocks: u64,
    pub pow_checks: u64,
}

impl Ledger {
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            state: self.state.clone(),

            journals: self.journals.clone(),
        }
    }

    /// Restore trusted local snapshot data against previously validated history.
    /// Checks state-root, supply, registry and journal consistency; this entry
    /// point does not replay transactions or verify the history's proof of work.
    /// Untrusted history needs block admission/replay or the PoW-checking restore.
    pub fn from_snapshot(snapshot: LedgerSnapshot, blocks: &[Block]) -> Result<Self, LedgerError> {
        Self::restore_snapshot_blocks(
            snapshot,
            blocks.iter().cloned(),
            usize::MAX,
            usize::MAX,
            false,
        )
        .map(|(ledger, _)| ledger)
    }

    /// Restore a local snapshot with streaming historical bodies and a bounded
    /// resident cache. The supplied history must have been fully validated locally.
    pub fn from_snapshot_with_body_cache(
        snapshot: LedgerSnapshot,
        blocks: impl IntoIterator<Item = Block>,
        max_body_bytes: usize,
        max_body_blocks: usize,
    ) -> Result<Self, LedgerError> {
        Self::from_snapshot_with_body_cache_measured(
            snapshot,
            blocks,
            max_body_bytes,
            max_body_blocks,
        )
        .map(|(ledger, _)| ledger)
    }

    /// Restore with full historical PoW checks and collect timing information.
    pub fn from_snapshot_with_body_cache_measured(
        snapshot: LedgerSnapshot,
        blocks: impl IntoIterator<Item = Block>,
        max_body_bytes: usize,
        max_body_blocks: usize,
    ) -> Result<(Self, SnapshotRestoreMetrics), LedgerError> {
        Self::restore_snapshot_blocks(snapshot, blocks, max_body_bytes, max_body_blocks, true)
    }

    /// Restore an already validated local prefix without repeating its PoW.
    /// The caller must bind the exact history and snapshot to a trusted local
    /// validation checkpoint. Peer/import/recovery data must use the full path.
    pub fn from_trusted_snapshot_with_body_cache_measured(
        snapshot: LedgerSnapshot,
        blocks: impl IntoIterator<Item = Block>,
        max_body_bytes: usize,
        max_body_blocks: usize,
    ) -> Result<(Self, SnapshotRestoreMetrics), LedgerError> {
        Self::restore_snapshot_blocks(snapshot, blocks, max_body_bytes, max_body_blocks, false)
    }

    fn restore_snapshot_blocks(
        snapshot: LedgerSnapshot,
        blocks: impl IntoIterator<Item = Block>,
        max_body_bytes: usize,
        max_body_blocks: usize,
        verify_pow: bool,
    ) -> Result<(Self, SnapshotRestoreMetrics), LedgerError> {
        let mut metrics = SnapshotRestoreMetrics::default();
        let mut genesis_hash = None;
        let mut tip = None;
        let journal_start = snapshot
            .journals
            .first_key_value()
            .map(|(height, _)| *height)
            .ok_or(LedgerError::MissingRollbackJournal)?;
        let mut retained_count = 0_usize;

        let mut chain = Chain::new();
        let mut pow_memory = None;

        let history_start = Instant::now();
        for block in blocks {
            metrics.blocks += 1;
            if verify_pow {
                let pow_start = Instant::now();
                if block.is_genesis() {
                    crate::consensus::validate_block_for_apply(&block, &chain)?;
                } else {
                    metrics.pow_checks += 1;
                    crate::consensus::validate_block_for_apply_with_memory(
                        &block,
                        &chain,
                        pow_memory.get_or_insert_with(crate::consensus::new_pow_memory),
                    )?;
                }
                metrics.proof_of_work += pow_start.elapsed();
            } else {
                block.validate_structure().map_err(ConsensusError::from)?;
            }

            if genesis_hash.is_none() {
                genesis_hash = Some(block.hash()?);
            }

            tip = Some((block.height(), block.state_root()));
            chain.insert_block(block.clone())?;
            chain.retain_recent_bodies(max_body_bytes, max_body_blocks)?;

            let expected_journals = usize::from(block.emission().is_some())
                .checked_add(block.operations().len())
                .ok_or(LedgerError::MissingRollbackJournal)?;

            if block.height() >= journal_start {
                if snapshot.journals.get(&block.height()).map(Vec::len) != Some(expected_journals) {
                    return Err(LedgerError::MissingRollbackJournal);
                }
                retained_count += 1;
            }
        }

        metrics.history = history_start
            .elapsed()
            .saturating_sub(metrics.proof_of_work);
        if snapshot.journals.len() != retained_count {
            return Err(LedgerError::MissingRollbackJournal);
        }
        drop(pow_memory);

        let (tip_height, tip_root) = tip.ok_or(LedgerError::EmptyChain)?;
        let ledger = Self {
            applications: Default::default(),
            chain,

            state: snapshot.state,

            journals: snapshot.journals,

            chain_context: Some(crate::common::ChainContext::new(
                genesis_hash.ok_or(LedgerError::EmptyChain)?.into_bytes(),
            )),
        };

        let start = Instant::now();
        ledger.state.audit_supply_invariants()?;
        metrics.supply_audit = start.elapsed();
        let start = Instant::now();
        ledger
            .state
            .programs
            .validate(tip_height)
            .map_err(|_| LedgerError::InvalidProgramState)?;

        metrics.registry = start.elapsed();
        let start = Instant::now();
        if ledger.state_root()? != tip_root {
            return Err(LedgerError::InvalidStateRoot);
        }

        metrics.state_root = start.elapsed();
        Ok((ledger, metrics))
    }
}
