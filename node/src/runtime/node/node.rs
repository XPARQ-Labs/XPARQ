use crate::runtime::cache::CoreCache;
use crate::runtime::mempool::Mempool;
use crate::runtime::mempool::MempoolError;
use crate::runtime::node::error::NodeError;
use crate::runtime::params::HASH_SIZE;
use crate::runtime::reorg_journal::{ReorgTransaction, ReorgTransactionStatus};
use crate::runtime::storage::Storage;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use xparq::block::{Block, BlockHeight, Height};
use xparq::consensus::supply::Amount;
use xparq::consensus::{
    Consensus, MIN_DIFFICULTY, WBDA_WINDOW, is_wbda_epoch_boundary, next_difficulty_from_window,
};
use xparq::crypto::{Address, BlockHash, Hash, TransactionHash};
use xparq::genesis::{GenesisError, genesis_hash, genesis_ledger};
use xparq::ledger::fork_choice::ForkChoice;
use xparq::ledger::{Chain, Checkpoint, CheckpointSet, FINALITY_DEPTH, Ledger};
use xparq::transaction::{SignedProtocolTransaction, SignedQCashTransaction, SignedTransfer};

const MAX_ORPHAN_BLOCKS: usize = 1024;
const MAX_ORPHAN_HEIGHT_DISTANCE: u64 = 512;
const ORPHAN_BLOCK_TTL_SECS: u64 = 10 * 60;
const MISSING_PARENT_RETRY_SECS: u64 = 5;

#[derive(Clone, Debug)]
struct OrphanBlock {
    block: Block,
    received_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingBalance {
    pub incoming: Amount,
    pub outgoing: Amount,
}

impl Default for PendingBalance {
    fn default() -> Self {
        Self {
            incoming: Amount(0),
            outgoing: Amount(0),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftBasis {
    pub signer: Address,
    pub live_balance: Amount,
    pub available_balance: Amount,
    pub spendable_after_pending: Amount,
    pub tip_height: BlockHeight,
    pub finalized_height: BlockHeight,
    pub pending_incoming: Amount,
    pub pending_outgoing: Amount,
    pub pending_outgoing_hashes: Vec<TransactionHash>,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub ledger: Ledger,
    pub mempool: Mempool,
    pub storage: Storage,
    pub consensus: Consensus,
    pub cache: CoreCache,
    pub fork_choice: ForkChoice,
    checkpoints: CheckpointSet,
    genesis_accounts: BTreeMap<Address, xparq::state::Account>,
    orphan_blocks: BTreeMap<BlockHash, OrphanBlock>,
    orphan_children_by_parent: BTreeMap<BlockHash, Vec<BlockHash>>,
    missing_parent_requests: VecDeque<BlockHash>,
    missing_parent_request_set: BTreeSet<BlockHash>,
    missing_parent_retry_at: BTreeMap<BlockHash, u64>,
    pending_compact_blocks: BTreeMap<BlockHash, crate::runtime::network::CompactBlock>,
    snapshot_cache: Option<(BlockHash, Vec<u8>)>,
    block_validation_failures_total: u64,
    reorgs_total: u64,
}

impl Node {
    #[cfg(test)]
    pub fn new(ledger: Ledger, storage: Storage, consensus: Consensus) -> Self {
        let genesis_accounts = if ledger.tip_height() == Some(Height(0)) {
            ledger.accounts().clone()
        } else {
            BTreeMap::new()
        };
        Self::with_genesis_accounts(ledger, storage, consensus, genesis_accounts)
    }

    #[cfg(test)]
    pub fn with_genesis_accounts(
        ledger: Ledger,
        storage: Storage,
        consensus: Consensus,
        genesis_accounts: BTreeMap<Address, xparq::state::Account>,
    ) -> Self {
        let expected_genesis = ledger
            .chain
            .header(&Height(0))
            .and_then(|header| header.hash().ok())
            .or_else(|| genesis_hash().ok().map(Into::into))
            .expect("test ledger must contain a valid genesis header");
        Self::try_with_genesis_accounts(
            ledger,
            storage,
            consensus,
            genesis_accounts,
            expected_genesis,
        )
        .expect("test ledger must build a valid fork choice index")
    }

    fn try_with_genesis_accounts(
        ledger: Ledger,
        storage: Storage,
        consensus: Consensus,
        genesis_accounts: BTreeMap<Address, xparq::state::Account>,
        expected_genesis: BlockHash,
    ) -> Result<Self, NodeError> {
        let cache = CoreCache::from_ledger(&ledger)?;
        let mut fork_choice = ForkChoice::new(expected_genesis);
        for (height, header) in &ledger.chain.headers {
            if let Some(block) = ledger.chain.blocks.get(height) {
                fork_choice.insert_block(block.clone())?;
            } else {
                fork_choice
                    .insert_header(xparq::ledger::ChainHeader::new(*height, header.clone()))?;
            }
        }
        let mut node = Self {
            ledger,
            mempool: Mempool::new(),
            storage,
            consensus,
            cache,
            fork_choice,
            checkpoints: CheckpointSet::empty(),
            genesis_accounts,
            orphan_blocks: BTreeMap::new(),
            orphan_children_by_parent: BTreeMap::new(),
            missing_parent_requests: VecDeque::new(),
            missing_parent_request_set: BTreeSet::new(),
            missing_parent_retry_at: BTreeMap::new(),
            pending_compact_blocks: BTreeMap::new(),
            snapshot_cache: None,
            block_validation_failures_total: 0,
            reorgs_total: 0,
        };
        node.restore_trusted_checkpoint()?;
        Ok(node)
    }

    pub fn block_validation_failures_total(&self) -> u64 {
        self.block_validation_failures_total
    }

    pub fn reorgs_total(&self) -> u64 {
        self.reorgs_total
    }

    pub fn stage_compact_block(
        &mut self,
        block_hash: BlockHash,
        compact: crate::runtime::network::CompactBlock,
    ) {
        const MAX_PENDING_COMPACT_BLOCKS: usize = 64;
        if self.pending_compact_blocks.len() >= MAX_PENDING_COMPACT_BLOCKS
            && let Some(oldest) = self.pending_compact_blocks.keys().next().copied()
        {
            self.pending_compact_blocks.remove(&oldest);
        }
        self.pending_compact_blocks.insert(block_hash, compact);
    }

    pub fn take_compact_block(
        &mut self,
        block_hash: &BlockHash,
    ) -> Option<crate::runtime::network::CompactBlock> {
        self.pending_compact_blocks.remove(block_hash)
    }

    pub fn snapshot_bytes(&mut self) -> Result<&[u8], NodeError> {
        let tip = self.tip_hash().ok_or(NodeError::MissingActiveTip)?;
        if self
            .snapshot_cache
            .as_ref()
            .is_none_or(|(cached_tip, _)| *cached_tip != tip)
        {
            self.snapshot_cache = Some((tip, xparq::genesis::snapshot_xparq_bytes(&self.ledger)?));
        }
        Ok(&self
            .snapshot_cache
            .as_ref()
            .ok_or(NodeError::MissingActiveTip)?
            .1)
    }

    pub fn submit_qcash_transaction(
        &mut self,
        transaction: SignedQCashTransaction,
    ) -> Result<TransactionHash, NodeError> {
        self.submit_protocol_transaction(transaction.into())
    }

    #[cfg(test)]
    pub fn temporary(ledger: Ledger, consensus: Consensus) -> Result<Self, NodeError> {
        Ok(Self::new(ledger, Storage::temporary()?, consensus))
    }

    pub fn init_or_load(path: impl AsRef<Path>, consensus: Consensus) -> Result<Self, NodeError> {
        let path = path.as_ref();
        let storage = Storage::open(path)?;
        let ledger = if storage.load_tip()?.is_some() {
            storage.load_ledger()?
        } else {
            let ledger = genesis_ledger()?;
            storage.save_ledger(&ledger)?;
            ledger
        };
        ensure_expected_genesis(&ledger)?;

        let genesis_accounts = match storage.load_genesis_accounts()? {
            Some(accounts) => accounts,
            None => {
                let accounts = if ledger.tip_height().is_none() {
                    BTreeMap::new()
                } else if ledger.tip_height() == Some(Height(0)) {
                    ledger.accounts().clone()
                } else {
                    let genesis = storage
                        .load_block_by_height(Height(0))?
                        .ok_or(NodeError::MissingGenesisState)?;
                    let mut genesis_ledger = Ledger::new();
                    genesis_ledger.apply_block(genesis.clone())?;
                    genesis_ledger.accounts().clone()
                };
                storage.save_genesis_accounts(&accounts)?;
                accounts
            }
        };
        let mut node = Self::try_with_genesis_accounts(
            ledger,
            storage,
            consensus,
            genesis_accounts,
            genesis_hash()?.into(),
        )?;
        node.index_stored_blocks()?;
        node.reconcile_indexed_fork_choice()?;
        node.retry_reorg_transactions()?;
        Ok(node)
    }

    pub fn submit_transaction(
        &mut self,
        transaction: SignedTransfer,
    ) -> Result<TransactionHash, NodeError> {
        self.mempool
            .insert_validated(&self.ledger, transaction.into())
            .map_err(NodeError::from)
    }

    pub fn submit_protocol_transaction(
        &mut self,
        transaction: SignedProtocolTransaction,
    ) -> Result<TransactionHash, NodeError> {
        self.mempool
            .insert_validated(&self.ledger, transaction)
            .map_err(NodeError::from)
    }

    pub fn apply_block(&mut self, block: Block) -> Result<(), NodeError> {
        self.prune_expired_orphans(current_unix_timestamp());
        if self.fork_choice.contains(&block.hash()?) {
            return Ok(());
        }
        match self.apply_known_parent_block(block.clone()) {
            Ok(()) => {
                self.process_orphans_for_parent(block.hash()?)?;
                Ok(())
            }
            Err(NodeError::ForkChoice(
                xparq::ledger::fork_choice::ForkChoiceError::MissingParent,
            )) => {
                self.cache_orphan_block(block)?;
                Ok(())
            }
            Err(NodeError::ForkChoice(
                xparq::ledger::fork_choice::ForkChoiceError::DuplicateBlock,
            )) => Ok(()),
            Err(NodeError::Ledger(xparq::ledger::LedgerError::DuplicateBlock)) => Ok(()),
            Err(error) => {
                self.block_validation_failures_total =
                    self.block_validation_failures_total.saturating_add(1);
                Err(error)
            }
        }
    }

    fn apply_known_parent_block(&mut self, block: Block) -> Result<(), NodeError> {
        self.validate_block_for_known_parent(&block)?;
        let active_staged = self.validate_block_state_for_known_parent(&block)?;
        let block_hash = self.fork_choice.insert_block(block.clone())?;
        let best_tip_hash = self.fork_choice.best_tip().map(|node| node.hash);

        if best_tip_hash != Some(block_hash) {
            self.storage.save_side_block(&block)?;
            return Ok(());
        }

        let extends_active_tip = match self.ledger.tip_hash() {
            Some(tip_hash) => block.previous_hash() == tip_hash,
            None => block.height().0 == 0,
        };
        if !extends_active_tip {
            return self.reorg_to_best_tip();
        }

        let previous_ledger = std::mem::replace(
            &mut self.ledger,
            active_staged.ok_or(NodeError::MissingStagedLedger)?,
        );
        self.snapshot_cache = None;
        if block.is_genesis() {
            self.genesis_accounts = self.ledger.accounts().clone();
            self.storage.save_genesis_accounts(&self.genesis_accounts)?;
        }
        self.mempool.remove_confirmed(&block)?;
        self.mark_reorg_transactions_reconfirmed(&block)?;
        self.cache.insert_block(block.clone())?;
        self.prune_finalized_state()?;
        self.storage
            .save_active_extension(&previous_ledger, &self.ledger, &block)?;
        Ok(())
    }

    fn cache_orphan_block(&mut self, block: Block) -> Result<(), NodeError> {
        let now = current_unix_timestamp();
        self.prune_expired_orphans(now);
        if block.height().0 == 0 {
            return Ok(());
        }
        if self.orphan_is_too_far_ahead(&block) {
            return Ok(());
        }

        let hash = block.hash()?;
        if self.fork_choice.contains(&hash) || self.orphan_blocks.contains_key(&hash) {
            return Ok(());
        }

        if self.orphan_blocks.len() >= MAX_ORPHAN_BLOCKS
            && let Some(evicted_hash) = self.orphan_blocks.keys().next().copied()
        {
            self.remove_orphan(evicted_hash);
        }

        let parent = BlockHash::from(block.previous_hash().as_hash());
        self.queue_missing_parent_request(parent);
        self.orphan_children_by_parent
            .entry(parent)
            .or_default()
            .push(hash);
        self.orphan_blocks.insert(
            hash,
            OrphanBlock {
                block,
                received_at: now,
            },
        );
        Ok(())
    }

    fn queue_missing_parent_request(&mut self, hash: BlockHash) {
        if self.fork_choice.contains(&hash) {
            return;
        }
        self.queue_missing_parent_request_at(hash, current_unix_timestamp());
    }

    fn queue_missing_parent_request_at(&mut self, hash: BlockHash, retry_at: u64) {
        if self.fork_choice.contains(&hash) {
            return;
        }
        self.missing_parent_retry_at
            .entry(hash)
            .and_modify(|existing| *existing = (*existing).min(retry_at))
            .or_insert(retry_at);
        if self.missing_parent_request_set.insert(hash) {
            self.missing_parent_requests.push_back(hash);
        }
    }

    pub fn drain_missing_parent_requests(&mut self) -> Vec<BlockHash> {
        self.drain_missing_parent_requests_at(current_unix_timestamp())
    }

    fn drain_missing_parent_requests_at(&mut self, now: u64) -> Vec<BlockHash> {
        let mut ready = Vec::new();
        let mut pending = VecDeque::new();
        while let Some(hash) = self.missing_parent_requests.pop_front() {
            let retry_at = self
                .missing_parent_retry_at
                .get(&hash)
                .copied()
                .unwrap_or(0);
            if retry_at <= now {
                self.missing_parent_request_set.remove(&hash);
                self.missing_parent_retry_at.remove(&hash);
                ready.push(hash);
            } else {
                pending.push_back(hash);
            }
        }
        self.missing_parent_requests = pending;
        ready
    }

    pub fn retry_missing_parent_request(&mut self, hash: BlockHash) {
        self.queue_missing_parent_request_at(
            hash,
            current_unix_timestamp().saturating_add(MISSING_PARENT_RETRY_SECS),
        );
    }

    fn orphan_is_too_far_ahead(&self, block: &Block) -> bool {
        let tip_height = self.ledger.tip_height().map(|height| height.0).unwrap_or(0);
        block.height().0 > tip_height.saturating_add(MAX_ORPHAN_HEIGHT_DISTANCE)
    }

    fn remove_orphan(&mut self, hash: BlockHash) {
        self.remove_orphan_index(hash);
        self.orphan_blocks.remove(&hash);
    }

    fn remove_orphan_index(&mut self, hash: BlockHash) {
        let empty_parents: Vec<_> = self
            .orphan_children_by_parent
            .iter_mut()
            .filter_map(|(parent, children)| {
                children.retain(|child| *child != hash);
                children.is_empty().then_some(*parent)
            })
            .collect();
        for parent in empty_parents {
            self.orphan_children_by_parent.remove(&parent);
        }
    }

    fn prune_expired_orphans(&mut self, now: u64) {
        let expired: Vec<_> = self
            .orphan_blocks
            .iter()
            .filter_map(|(hash, orphan)| {
                let expired = now.saturating_sub(orphan.received_at) > ORPHAN_BLOCK_TTL_SECS
                    || self.orphan_is_too_far_ahead(&orphan.block);
                expired.then_some(*hash)
            })
            .collect();
        for hash in expired {
            self.remove_orphan(hash);
        }
    }

    fn process_orphans_for_parent(&mut self, parent_hash: BlockHash) -> Result<(), NodeError> {
        self.prune_expired_orphans(current_unix_timestamp());
        let mut parents = vec![parent_hash];

        while let Some(parent) = parents.pop() {
            let Some(children) = self.orphan_children_by_parent.remove(&parent) else {
                continue;
            };

            for child_hash in children {
                let Some(orphan) = self.orphan_blocks.remove(&child_hash) else {
                    continue;
                };
                let child = orphan.block;

                match self.apply_known_parent_block(child.clone()) {
                    Ok(()) => parents.push(child_hash),
                    Err(NodeError::ForkChoice(
                        xparq::ledger::fork_choice::ForkChoiceError::MissingParent,
                    )) => self.cache_orphan_block(child)?,
                    Err(_) => {}
                }
            }
        }
        Ok(())
    }

    fn validate_block_state_for_known_parent(
        &self,
        block: &Block,
    ) -> Result<Option<Ledger>, NodeError> {
        let extends_active_tip = match self.ledger.tip_hash() {
            Some(tip_hash) => block.previous_hash() == tip_hash,
            None => block.height().0 == 0,
        };

        if extends_active_tip {
            let (ledger, _) = self.ledger.validate_and_execute_block(block)?;
            return Ok(Some(ledger));
        }

        let parent_hash = BlockHash::from(block.previous_hash().as_hash());
        let ledger = self.ledger_for_branch_tip(parent_hash)?;
        Self::validate_canonical_state_root(&ledger, block)?;
        Ok(None)
    }

    fn validate_canonical_state_root(ledger: &Ledger, block: &Block) -> Result<(), NodeError> {
        let expected_state_root = ledger.state_root_after_block(block)?;
        if block.state_root() != expected_state_root {
            return Err(xparq::ledger::LedgerError::InvalidStateRoot.into());
        }
        if !block.is_genesis() && block.state_root() == Hash([0; HASH_SIZE]) {
            return Err(xparq::ledger::LedgerError::InvalidStateRoot.into());
        }
        Ok(())
    }

    fn reorg_to_best_tip(&mut self) -> Result<(), NodeError> {
        let old_tip_hash = self.ledger.tip_hash();
        let old_tip_height = self
            .ledger
            .tip_height()
            .ok_or(NodeError::MissingActiveTip)?;
        let best_tip_node = self
            .fork_choice
            .best_tip()
            .ok_or(NodeError::MissingBestTip)?;
        let best_tip = best_tip_node.hash;
        let best_tip_height = best_tip_node.height;
        let ancestor = self
            .common_ancestor(old_tip_hash, best_tip)
            .ok_or(NodeError::MissingCommonAncestor)?;
        let ancestor_height = self
            .fork_choice
            .get(&ancestor)
            .ok_or(NodeError::MissingForkNode)?
            .height;
        let disconnected_depth = old_tip_height.0.saturating_sub(ancestor_height.0);
        let connected_depth = best_tip_height.0.saturating_sub(ancestor_height.0);
        if disconnected_depth > u64::from(FINALITY_DEPTH) {
            crate::node_warn!(
                "REORG",
                "deep_reorg_detected ancestor_height={} old_height={} new_height={} disconnected_blocks={} connected_blocks={}",
                ancestor_height.0,
                old_tip_height.0,
                best_tip_height.0,
                disconnected_depth,
                connected_depth
            );
        }
        if !self.checkpoints.is_compatible(&self.fork_choice, best_tip)
            || xparq::ledger::reorg_crosses_checkpoint(
                &self.fork_choice,
                &self.checkpoints,
                ancestor,
            )?
        {
            return Err(xparq::ledger::LedgerError::FinalityViolation.into());
        }
        let winning_branch = self
            .fork_choice
            .branch_from_ancestor(ancestor, best_tip)
            .ok_or(NodeError::MissingForkBranch)?;
        let mut disconnected = Vec::new();
        let mut current = old_tip_hash.ok_or(NodeError::MissingActiveTip)?;
        while current != ancestor {
            let fork_node = self
                .fork_choice
                .get(&current)
                .ok_or(NodeError::MissingForkNode)?;
            disconnected.push((
                fork_node.block.clone(),
                self.ledger.events_for_block(&current).to_vec(),
            ));
            current = fork_node.parent;
        }
        let mut disconnected_transaction_ids = Vec::new();
        let mut disconnected_transaction_hashes = Vec::new();
        for (old_block, _) in &disconnected {
            let old_block_hash = old_block.hash()?;
            for (transaction_index, transaction) in
                old_block.transactions().iter().cloned().enumerate()
            {
                let transaction_index = u32::try_from(transaction_index)
                    .map_err(|_| NodeError::TransactionIndexOverflow)?;
                let record = ReorgTransaction::new(
                    old_block.height(),
                    old_block_hash,
                    transaction_index,
                    transaction,
                    current_unix_timestamp(),
                )?;
                disconnected_transaction_ids.push(record.id);
                disconnected_transaction_hashes.push(record.transaction_hash);
                self.storage.save_reorg_transaction(&record)?;
            }
        }

        self.ledger = self.ledger_for_branch_tip(best_tip)?;
        self.snapshot_cache = None;
        self.cache = CoreCache::from_ledger(&self.ledger)?;
        for block in &winning_branch {
            self.mempool.remove_confirmed(block)?;
        }
        self.mempool.revalidate_after_reorg(&self.ledger)?;
        self.prune_finalized_state()?;
        self.storage
            .save_reorg(&self.ledger, &disconnected, &winning_branch)?;
        self.retry_reorg_transactions()?;

        let mut requeued_transactions = 0usize;
        let mut conflicting_transactions = 0usize;
        let mut reconfirmed_transactions = 0usize;
        for id in disconnected_transaction_ids {
            let Some(record) = self.storage.load_reorg_transaction(&id)? else {
                continue;
            };
            match record.status {
                ReorgTransactionStatus::Requeued => {
                    requeued_transactions = requeued_transactions.saturating_add(1)
                }
                ReorgTransactionStatus::Conflict => {
                    conflicting_transactions = conflicting_transactions.saturating_add(1)
                }
                ReorgTransactionStatus::Reconfirmed { .. } => {
                    reconfirmed_transactions = reconfirmed_transactions.saturating_add(1)
                }
                ReorgTransactionStatus::Pending => {}
            }
        }
        let transaction_sample = disconnected_transaction_hashes
            .iter()
            .take(16)
            .map(|hash| hex::encode(hash.0))
            .collect::<Vec<_>>()
            .join(",");
        crate::node_info!(
            "REORG",
            "reconciled ancestor_height={} old_height={} new_height={} disconnected_blocks={} connected_blocks={} disconnected_transactions={} requeued={} conflicts={} reconfirmed={} transaction_hash_sample=[{}] omitted_transaction_hashes={}",
            ancestor_height.0,
            old_tip_height.0,
            best_tip_height.0,
            disconnected_depth,
            connected_depth,
            disconnected_transaction_hashes.len(),
            requeued_transactions,
            conflicting_transactions,
            reconfirmed_transactions,
            transaction_sample,
            disconnected_transaction_hashes.len().saturating_sub(16)
        );

        self.reorgs_total = self.reorgs_total.saturating_add(1);
        Ok(())
    }

    fn restore_trusted_checkpoint(&mut self) -> Result<(), NodeError> {
        if let Some(height) = self.ledger.chain.checkpoint_height {
            let hash = self
                .ledger
                .chain
                .header(&height)
                .ok_or(NodeError::MissingDifficultyAnchor)?
                .hash()?;
            self.checkpoints.insert(Checkpoint { height, hash })?;
        }
        Ok(())
    }

    fn retry_reorg_transactions(&mut self) -> Result<(), NodeError> {
        for mut record in self.storage.load_reorg_transactions()? {
            if !record.is_reconfirmed() {
                self.retry_reorg_transaction_record(&mut record)?;
            }
        }
        Ok(())
    }

    fn retry_reorg_transaction_record(
        &mut self,
        record: &mut ReorgTransaction,
    ) -> Result<(), NodeError> {
        if let Some((block_height, block_hash)) =
            self.canonical_transaction_location(record.transaction_hash)?
        {
            record.status = ReorgTransactionStatus::Reconfirmed {
                block_height,
                block_hash,
            };
            record.last_error = None;
            self.storage.save_reorg_transaction(record)?;
            return Ok(());
        }
        record.retry_attempts = record.retry_attempts.saturating_add(1);
        match self.submit_protocol_transaction(record.transaction.clone()) {
            Ok(_) | Err(NodeError::Mempool(MempoolError::DuplicateTransaction)) => {
                record.status = ReorgTransactionStatus::Requeued;
                record.last_error = None;
            }
            Err(error) => {
                record.status = ReorgTransactionStatus::Conflict;
                record.last_error = Some(error.to_string());
            }
        }
        self.storage.save_reorg_transaction(record)?;
        Ok(())
    }

    fn canonical_transaction_location(
        &self,
        transaction_hash: TransactionHash,
    ) -> Result<Option<(BlockHeight, BlockHash)>, NodeError> {
        for block in self.ledger.chain.blocks.values() {
            for transaction in block.transactions() {
                if transaction.hash()? == transaction_hash {
                    return Ok(Some((block.height(), block.hash()?)));
                }
            }
        }
        Ok(None)
    }

    fn mark_reorg_transactions_reconfirmed(&self, block: &Block) -> Result<(), NodeError> {
        let block_hash = block.hash()?;
        for transaction in block.transactions() {
            let transaction_hash = transaction.hash()?;
            for mut record in self
                .storage
                .load_reorg_transactions()?
                .into_iter()
                .filter(|record| {
                    record.transaction_hash == transaction_hash && !record.is_reconfirmed()
                })
            {
                record.status = ReorgTransactionStatus::Reconfirmed {
                    block_height: block.height(),
                    block_hash,
                };
                record.last_error = None;
                self.storage.save_reorg_transaction(&record)?;
            }
        }
        Ok(())
    }

    fn ledger_for_branch_tip(&self, tip: BlockHash) -> Result<Ledger, NodeError> {
        if self.ledger.tip_hash() == Some(tip) {
            return Ok(self.ledger.clone());
        }
        let ancestor = self
            .common_ancestor(self.ledger.tip_hash(), tip)
            .ok_or(NodeError::MissingCommonAncestor)?;
        if !self.checkpoints.is_compatible(&self.fork_choice, tip)
            || xparq::ledger::reorg_crosses_checkpoint(
                &self.fork_choice,
                &self.checkpoints,
                ancestor,
            )?
        {
            return Err(xparq::ledger::LedgerError::FinalityViolation.into());
        }

        let mut disconnect = Vec::new();
        let mut current = self.ledger.tip_hash().ok_or(NodeError::MissingActiveTip)?;
        while current != ancestor {
            disconnect.push(current);
            current = self
                .fork_choice
                .get(&current)
                .ok_or(NodeError::MissingForkNode)?
                .parent;
        }

        let mut ledger = self.ledger.clone();
        match ledger.rollback_blocks(&disconnect) {
            Ok(_) => {}
            Err(xparq::ledger::LedgerError::MissingQCashAccountJournal) => {
                return self.ledger_for_branch_tip_from_genesis(tip);
            }
            Err(error) => return Err(error.into()),
        }
        let branch = self
            .fork_choice
            .branch_from_ancestor(ancestor, tip)
            .ok_or(NodeError::MissingForkBranch)?;
        for block in branch {
            ledger.apply_block(block)?;
        }

        Ok(ledger)
    }

    fn ledger_for_branch_tip_from_genesis(&self, tip: BlockHash) -> Result<Ledger, NodeError> {
        let genesis_hash = self
            .fork_choice
            .ancestor_hashes(tip)
            .last()
            .copied()
            .unwrap_or(tip);
        let genesis = self
            .fork_choice
            .get(&genesis_hash)
            .ok_or(NodeError::MissingForkNode)?
            .block
            .clone();
        let mut ledger =
            Ledger::from_accounts_and_chain(self.genesis_accounts.clone(), Chain::new())?;
        ledger.chain.insert_block(genesis)?;
        let branch = self
            .fork_choice
            .branch_from_ancestor(genesis_hash, tip)
            .ok_or(NodeError::MissingForkBranch)?;
        for block in branch {
            ledger.apply_block(block)?;
        }
        Ok(ledger)
    }

    fn index_stored_blocks(&mut self) -> Result<(), NodeError> {
        let mut blocks = self.storage.load_blocks_by_hash()?;
        blocks.sort_by_key(|block| block.height().0);

        let mut progressed = true;
        while progressed {
            progressed = false;
            let mut remaining = Vec::new();
            for block in blocks {
                let hash = block.hash()?;
                if self.fork_choice.contains(&hash) {
                    progressed = true;
                    continue;
                }
                match self.fork_choice.insert_block(block.clone()) {
                    Ok(_) => progressed = true,
                    Err(xparq::ledger::fork_choice::ForkChoiceError::MissingParent) => {
                        remaining.push(block);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            blocks = remaining;
        }

        Ok(())
    }

    /// Resolves every locally stored branch by cumulative work. A height
    /// boundary must never win merely because the active ledger reached it
    /// first, and local history must never create a hard checkpoint.
    fn reconcile_indexed_fork_choice(&mut self) -> Result<(), NodeError> {
        self.prune_finalized_state()?;
        let best_tip = self
            .fork_choice
            .best_tip()
            .ok_or(NodeError::MissingBestTip)?
            .hash;
        if self.ledger.tip_hash() != Some(best_tip) {
            self.reorg_to_best_tip()?;
        } else {
            self.prune_finalized_state()?;
            self.storage.save_ledger(&self.ledger)?;
        }
        Ok(())
    }

    fn prune_finalized_state(&mut self) -> Result<usize, NodeError> {
        let Some(checkpoint) = self.checkpoints.highest() else {
            return Ok(0);
        };
        if self
            .ledger
            .block(&checkpoint.height)
            .and_then(|block| block.hash().ok())
            != Some(checkpoint.hash)
        {
            return Ok(0);
        }
        self.ledger
            .prune_finalized_rollback_state(checkpoint.height);
        Ok(self.fork_choice.prune_finalized(checkpoint.hash)?)
    }

    fn common_ancestor(&self, old_tip: Option<BlockHash>, new_tip: BlockHash) -> Option<BlockHash> {
        let old_tip = old_tip?;
        let old_ancestors: std::collections::BTreeSet<_> = self
            .fork_choice
            .ancestor_hashes(old_tip)
            .into_iter()
            .collect();

        self.fork_choice
            .ancestor_hashes(new_tip)
            .into_iter()
            .find(|hash| old_ancestors.contains(hash))
    }

    fn validate_block_for_known_parent(&self, block: &Block) -> Result<(), NodeError> {
        let _now = current_unix_timestamp();
        if let Some(checkpoint_height) = self.ledger.chain.checkpoint_height {
            if block.height() <= checkpoint_height {
                return Err(NodeError::MissingCommonAncestor);
            }
            let parent = BlockHash(block.previous_hash().0);
            let branch_checkpoint = self
                .fork_choice
                .ancestor_hash_at_height(parent, checkpoint_height)
                .ok_or(NodeError::MissingCommonAncestor)?;
            let canonical_checkpoint = self
                .ledger
                .chain
                .header(&checkpoint_height)
                .ok_or(NodeError::MissingCommonAncestor)?
                .hash()?;
            if branch_checkpoint != canonical_checkpoint {
                return Err(NodeError::MissingCommonAncestor);
            }
        }
        if block.height().0 == 0 {
            self.consensus.validate_genesis_block(block)?;
            ensure_expected_genesis_hash(block)?;
            return Ok(());
        }

        let parent = self
            .fork_choice
            .get(&BlockHash::from(block.previous_hash().as_hash()))
            .ok_or(xparq::ledger::fork_choice::ForkChoiceError::MissingParent)?;
        if let Some(checkpoint) = self.checkpoints.highest()
            && (block.height() <= checkpoint.height
                || self
                    .fork_choice
                    .ancestor_hash_at_height(parent.hash, checkpoint.height)
                    != Some(checkpoint.hash))
        {
            return Err(xparq::ledger::LedgerError::FinalityViolation.into());
        }
        let expected_difficulty = self.next_difficulty_after_branch_tip(parent.hash)?;
        let validation_consensus = self.consensus;
        validation_consensus.validate_next_block_with_tip(
            block,
            &parent.block,
            expected_difficulty,
        )?;
        Ok(())
    }

    pub fn next_difficulty(&self) -> Result<u32, NodeError> {
        if self.consensus.difficulty() == 0 {
            return Ok(MIN_DIFFICULTY);
        }
        self.next_difficulty_after_tip(self.ledger.tip_height().unwrap_or(Height(0)))
    }

    pub fn next_difficulty_at(&self, block_timestamp: u64) -> Result<u32, NodeError> {
        let _ = block_timestamp;
        if self.consensus.difficulty() == 0 {
            return Ok(MIN_DIFFICULTY);
        }
        self.next_difficulty()
    }

    fn next_difficulty_after_tip(&self, tip_height: BlockHeight) -> Result<u32, NodeError> {
        if self.ledger.tip_height() != Some(tip_height) {
            return Err(NodeError::MissingDifficultyAnchor);
        }
        Ok(self
            .ledger
            .expected_difficulty_after_tip()?
            .max(MIN_DIFFICULTY))
    }

    fn next_difficulty_after_branch_tip(&self, tip_hash: BlockHash) -> Result<u32, NodeError> {
        let tip = self
            .fork_choice
            .get(&tip_hash)
            .ok_or(xparq::ledger::fork_choice::ForkChoiceError::MissingParent)?;
        let parent_difficulty = tip.block.difficulty().max(MIN_DIFFICULTY);
        let next_height = Height(tip.height.0.saturating_add(1));
        if !is_wbda_epoch_boundary(next_height.0) {
            return Ok(parent_difficulty);
        }

        let mut weights = Vec::with_capacity(WBDA_WINDOW);
        let mut current = tip_hash;
        for _ in 0..WBDA_WINDOW {
            let node = self
                .fork_choice
                .get(&current)
                .ok_or(NodeError::MissingDifficultyAnchor)?;
            weights.push(
                node.block
                    .block_weight()
                    .try_into()
                    .map_err(|_| NodeError::MissingDifficultyAnchor)?,
            );
            if node.height == Height(0) {
                break;
            }
            current = node.parent;
        }
        if weights.len() != WBDA_WINDOW {
            return Err(NodeError::MissingDifficultyAnchor);
        }
        weights.reverse();
        next_difficulty_from_window(parent_difficulty, &weights)
            .ok_or(NodeError::MissingDifficultyAnchor)
    }

    pub fn flush_to_storage(&self) -> Result<(), NodeError> {
        self.storage.save_ledger(&self.ledger)?;
        Ok(())
    }

    pub fn tip_height(&self) -> Option<BlockHeight> {
        self.ledger.tip_height()
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.ledger.tip_hash()
    }

    pub fn tip_work(&self) -> Option<[u64; 8]> {
        self.ledger
            .tip_hash()
            .and_then(|hash| self.fork_choice.get(&hash))
            .map(|node| node.cumulative_work.to_be_limbs())
    }

    pub fn pending_balance(&self, address: &Address) -> PendingBalance {
        let mut pending = PendingBalance::default();
        for transaction in self.mempool.transactions() {
            match transaction {
                SignedProtocolTransaction::Transfer(transaction) => {
                    for output in &transaction.transaction.outputs {
                        if output.to.address() == Some(*address) {
                            pending.incoming.0 = pending.incoming.0.saturating_add(output.amount.0);
                        }
                    }
                    if transaction.transaction.from == *address {
                        let input_total = transaction
                            .transaction
                            .inputs
                            .iter()
                            .filter_map(|id| self.ledger.xpq_utxos.coin(*id))
                            .fold(0_u64, |sum, coin| sum.saturating_add(coin.amount.0));
                        pending.outgoing.0 = pending.outgoing.0.saturating_add(input_total);
                    }
                }
                SignedProtocolTransaction::QCash(transaction) => {
                    if let xparq::transaction::QCashTransactionKind::Redeem { outputs, .. } =
                        &transaction.transaction.kind
                    {
                        for output in outputs {
                            if output.to.address() == Some(*address) {
                                pending.incoming.0 =
                                    pending.incoming.0.saturating_add(output.amount.0);
                            }
                        }
                    }
                    if transaction.transaction.signer == *address
                        && let xparq::transaction::QCashTransactionKind::Withdraw { amount, .. } =
                            &transaction.transaction.kind
                    {
                        pending.outgoing.0 = pending.outgoing.0.saturating_add(amount.0);
                    }
                }
            }
        }
        pending
    }

    pub fn draft_basis(&self, address: &Address) -> Option<DraftBasis> {
        self.ledger.account(address)?;
        let tip_height = self.ledger.tip_height()?;
        let live_balance = self.ledger.xpq_utxos.balance(*address).ok()?;
        let available_balance = self
            .ledger
            .xpq_utxos
            .available_balance(*address, tip_height)
            .ok()?;
        let pending = self.pending_balance(address);
        let spendable_after_pending =
            Amount(available_balance.0.saturating_sub(pending.outgoing.0));
        let pending_outgoing_hashes = self
            .mempool
            .transactions()
            .filter(|transaction| transaction.signer() == *address)
            .filter_map(|transaction| transaction.hash().ok())
            .collect();
        let finalized_height = Height(tip_height.0.saturating_sub(FINALITY_DEPTH as u64));
        Some(DraftBasis {
            signer: *address,
            live_balance,
            available_balance,
            spendable_after_pending,
            tip_height,
            finalized_height,
            pending_incoming: pending.incoming,
            pending_outgoing: pending.outgoing,
            pending_outgoing_hashes,
        })
    }
}

fn ensure_expected_genesis(ledger: &Ledger) -> Result<(), NodeError> {
    let Some(genesis) = ledger.block(&Height(0)) else {
        return Err(NodeError::MissingGenesisState);
    };
    ensure_expected_genesis_hash(genesis)
}

fn ensure_expected_genesis_hash(genesis: &Block) -> Result<(), NodeError> {
    let found = genesis.hash()?.0;
    let expected = genesis_hash()?.0;
    if found != expected {
        return Err(GenesisError::HashMismatch { expected, found }.into());
    }
    Ok(())
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod incremental_reorg_tests {
    use super::*;
    use crate::runtime::miner::{
        MiningConfig, mine_prepared_block_until_with_attempts, prepare_candidate_block,
    };
    use xparq::consensus::ConsensusConfig;

    fn mine_empty_block(
        ledger: &Ledger,
        consensus: &Consensus,
        miner: Address,
        start_nonce: u64,
    ) -> (Block, u64) {
        let candidate =
            prepare_candidate_block(&Mempool::new(), ledger, miner, 0, 0, 0, MIN_DIFFICULTY)
                .unwrap();
        let (result, attempted) = mine_prepared_block_until_with_attempts(
            candidate,
            consensus,
            MiningConfig {
                difficulty: MIN_DIFFICULTY,
                start_nonce,
                max_attempts: 256,
                transaction_limit: 0,
                min_fee_rate: 0,
            },
            || false,
        )
        .unwrap();
        (
            result
                .expect("difficulty-one test block must be mined")
                .block,
            attempted,
        )
    }

    #[test]
    fn shallow_reorg_rolls_back_only_to_common_ancestor() {
        let consensus = Consensus::new(ConsensusConfig::new(MIN_DIFFICULTY)).unwrap();
        let ledger = genesis_ledger().unwrap();
        let storage = Storage::temporary().unwrap();
        storage.save_ledger(&ledger).unwrap();
        let mut node = Node::new(ledger, storage, consensus);
        let miner = Address([0x71; xparq::crypto::ADDRESS_SIZE]);
        let mut next_nonce = 0;

        for _ in 0..2 {
            let (block, attempted) =
                mine_empty_block(&node.ledger, &node.consensus, miner, next_nonce);
            next_nonce = next_nonce.saturating_add(attempted);
            node.apply_block(block).unwrap();
        }

        let reloaded = node.storage.load_ledger().unwrap();
        node = Node::new(reloaded, node.storage.clone(), node.consensus);

        let ancestor_hash = node.tip_hash().unwrap();
        let ancestor_height = node.tip_height().unwrap();
        let ancestor_ledger = node.ledger.clone();
        let (first, attempted) =
            mine_empty_block(&ancestor_ledger, &node.consensus, miner, next_nonce);
        next_nonce = next_nonce.saturating_add(attempted);
        let (second, _) = mine_empty_block(&ancestor_ledger, &node.consensus, miner, next_nonce);
        let first_hash = first.hash().unwrap();
        let second_hash = second.hash().unwrap();
        assert_ne!(first_hash, second_hash);
        let (loser, winner) = if first_hash < second_hash {
            (second, first)
        } else {
            (first, second)
        };
        let loser_hash = loser.hash().unwrap();
        let winner_hash = winner.hash().unwrap();

        node.apply_block(loser).unwrap();
        assert_eq!(node.tip_hash(), Some(loser_hash));
        assert!(node.ledger.rollback_history().is_empty());

        node.apply_block(winner).unwrap();

        assert_eq!(node.tip_hash(), Some(winner_hash));
        assert_eq!(node.tip_height(), Some(Height(ancestor_height.0 + 1)));
        assert_eq!(node.reorgs_total(), 1);
        assert_eq!(node.ledger.rollback_history().len(), 1);
        let rollback = node.ledger.rollback_history().last().unwrap();
        assert_eq!(rollback.old_tip, loser_hash);
        assert_eq!(rollback.new_tip, ancestor_hash);
        assert_eq!(rollback.disconnected_blocks.len(), 1);
        assert!(
            node.storage
                .load_block_events(&loser_hash)
                .unwrap()
                .is_empty()
        );
        assert!(
            !node
                .storage
                .load_block_events(&winner_hash)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            node.storage
                .load_block_by_hash(&loser_hash)
                .unwrap()
                .unwrap()
                .hash()
                .unwrap(),
            loser_hash
        );
        let reloaded = node.storage.load_ledger().unwrap();
        assert_eq!(reloaded.tip_hash(), Some(winner_hash));
        assert_eq!(reloaded.state_root(), node.ledger.state_root());
        assert!(reloaded.rollback_state_before(&winner_hash).is_some());
    }
}

#[cfg(test)]
mod requeue_tests {
    use super::*;
    use xparq::block::Nonce;
    use xparq::consensus::ConsensusConfig;
    use xparq::consensus::supply::{Amount, XPQ};
    use xparq::crypto::{address_from_public_key, generate_keypair, sign};
    use xparq::qcash::{
        QCashCoinFile, QCashWithdrawalMetadata, qcash_redeem_key_commitment_from_secret,
    };
    use xparq::transaction::{
        QCashTransaction, SignedQCashTransaction, SignedTransfer, Transfer, TransferOutput,
    };

    fn test_genesis() -> Block {
        xparq::genesis::genesis_block().unwrap()
    }

    fn reorg_transaction(transaction: SignedProtocolTransaction) -> ReorgTransaction {
        let block = Block::from_protocol_transactions(
            Height(1),
            BlockHash([0x11; HASH_SIZE]),
            MIN_DIFFICULTY,
            Nonce(0),
            None,
            vec![transaction.clone()],
        )
        .unwrap();
        ReorgTransaction::new(block.height(), block.hash().unwrap(), 0, transaction, 1).unwrap()
    }

    fn test_node(ledger: Ledger) -> Node {
        let genesis_accounts = ledger.accounts().clone();
        Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(MIN_DIFFICULTY)).unwrap(),
            genesis_accounts,
        )
    }

    #[test]
    fn disconnected_utxo_transfer_is_requeued_without_resigning() {
        let owner = generate_keypair();
        let sender = address_from_public_key(&owner.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, owner.public_key, Amount(XPQ))
            .unwrap();
        let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
        ledger.chain.insert_block(test_genesis()).unwrap();
        let transaction = Transfer::new(
            sender,
            vec![input],
            Address([0x42; xparq::crypto::ADDRESS_SIZE]),
            Amount(XPQ - 10_000),
        )
        .with_output(TransferOutput::new(
            xparq::transaction::OutputTarget::BlockMiner,
            Amount(10_000),
        ));
        let payload = transaction.signing_bytes().unwrap();
        let signed = SignedTransfer::new(
            transaction,
            owner.public_key,
            sign(&owner.secret_key, &payload),
        );
        let mut record = reorg_transaction(signed.into());
        let hash = record.transaction_hash;
        let mut node = test_node(ledger);

        node.retry_reorg_transaction_record(&mut record).unwrap();

        assert_eq!(record.status, ReorgTransactionStatus::Requeued);
        assert!(node.mempool.contains(&hash));
    }

    #[test]
    fn persisted_reorg_transaction_is_retried_after_mempool_restart() {
        let owner = generate_keypair();
        let sender = address_from_public_key(&owner.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, owner.public_key, Amount(XPQ))
            .unwrap();
        let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
        ledger.chain.insert_block(test_genesis()).unwrap();
        let transaction = Transfer::new(
            sender,
            vec![input],
            Address([0x44; xparq::crypto::ADDRESS_SIZE]),
            Amount(XPQ - 10_000),
        )
        .with_output(TransferOutput::new(
            xparq::transaction::OutputTarget::BlockMiner,
            Amount(10_000),
        ));
        let payload = transaction.signing_bytes().unwrap();
        let signed = SignedTransfer::new(
            transaction,
            owner.public_key,
            sign(&owner.secret_key, &payload),
        );
        let record = reorg_transaction(signed.into());
        let hash = record.transaction_hash;
        let mut node = test_node(ledger);
        node.storage.save_reorg_transaction(&record).unwrap();

        node.retry_reorg_transactions().unwrap();
        assert!(node.mempool.contains(&hash));

        node.mempool = Mempool::new();
        node.retry_reorg_transactions().unwrap();

        assert!(node.mempool.contains(&hash));
        assert_eq!(
            node.storage
                .load_reorg_transaction(&record.id)
                .unwrap()
                .unwrap()
                .status,
            ReorgTransactionStatus::Requeued
        );
    }

    #[test]
    fn disconnected_qcash_redeem_is_requeued_without_the_bearer_file() {
        let owner = generate_keypair();
        let sender = address_from_public_key(&owner.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, owner.public_key, Amount(XPQ))
            .unwrap();
        let redeem_secret = [0x31; 32];
        let metadata = QCashWithdrawalMetadata::with_selected_amounts(
            &[Amount(XPQ)],
            &[qcash_redeem_key_commitment_from_secret(&redeem_secret)],
        )
        .unwrap();
        let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
        let withdraw = QCashTransaction::withdraw(
            sender,
            vec![input],
            Vec::new(),
            Amount(XPQ),
            metadata.clone(),
        );
        let withdraw_hash = withdraw.hash().unwrap();
        let payload = withdraw.signing_bytes().unwrap();
        let signed_withdraw = SignedQCashTransaction::new(
            withdraw,
            owner.public_key,
            sign(&owner.secret_key, &payload),
        );
        ledger
            .apply_signed_qcash_transaction(&signed_withdraw, Height(0))
            .unwrap();
        ledger.chain.insert_block(test_genesis()).unwrap();

        let cash_file =
            QCashCoinFile::new(withdraw_hash, &metadata.outputs[0], redeem_secret).unwrap();
        let redeem = QCashTransaction::redeem_from_files(
            sender,
            vec![
                TransferOutput::new(
                    Address([0x43; xparq::crypto::ADDRESS_SIZE]),
                    Amount(XPQ - 10_000),
                ),
                TransferOutput::new(xparq::transaction::OutputTarget::BlockMiner, Amount(10_000)),
            ],
            &[cash_file],
        )
        .unwrap();
        let payload = redeem.signing_bytes().unwrap();
        let signed_redeem =
            SignedQCashTransaction::new_stored(redeem, sign(&owner.secret_key, &payload));
        let mut record = reorg_transaction(signed_redeem.into());
        let hash = record.transaction_hash;
        let mut node = test_node(ledger);

        node.retry_reorg_transaction_record(&mut record).unwrap();

        assert_eq!(record.status, ReorgTransactionStatus::Requeued);
        assert!(node.mempool.contains(&hash));
    }
}

#[cfg(test)]
mod header_first_sync_tests {
    use super::*;
    use xparq::block::{EmissionTransaction, Nonce};
    use xparq::consensus::ConsensusConfig;

    #[test]
    fn rejects_invalid_pow_header_before_it_enters_fork_choice() {
        let ledger = genesis_ledger().unwrap();
        let parent = ledger.tip_hash().unwrap();
        let node = Node::new(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(MIN_DIFFICULTY)).unwrap(),
        );
        let mut block = Block::from_protocol_transactions(
            Height(1),
            parent,
            MIN_DIFFICULTY,
            Nonce(0),
            Some(EmissionTransaction::new(
                Address([7; xparq::crypto::ADDRESS_SIZE]),
                Amount(0),
            )),
            Vec::new(),
        )
        .unwrap();
        while Consensus::validate_pow_at_difficulty(&block, MIN_DIFFICULTY).is_ok() {
            block.header.nonce.0 = block.header.nonce.0.saturating_add(1);
        }
        let hash = block.hash().unwrap();
        let headers = [xparq::ledger::ChainHeader::new(
            block.height(),
            block.header,
        )];

        let mut preview = node.fork_choice.clone();
        assert!(preview.insert_header(headers[0].clone()).is_err());
        assert!(!node.fork_choice.contains(&hash));
        assert_eq!(node.ledger.chain.checkpoint_height, None);
    }
}
