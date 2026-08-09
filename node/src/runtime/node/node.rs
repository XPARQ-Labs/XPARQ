use crate::runtime::cache::CoreCache;
use crate::runtime::mempool::Mempool;
use crate::runtime::mempool::MempoolError;
use crate::runtime::miner::{MiningConfig, MiningResult, mine_candidate_block};
use crate::runtime::node::error::NodeError;
use crate::runtime::params::HASH_SIZE;
use crate::runtime::recovery::{
    RollbackIssue, RollbackIssueId, RollbackProofContext, RollbackRecoveryStatus,
};
use crate::runtime::storage::Storage;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use xparq::block::{Block, BlockHeight, Height};
use xparq::consensus::supply::{Amount, Balance};
use xparq::consensus::{
    Consensus, MIN_DIFFICULTY, WBDA_WINDOW, is_wbda_epoch_boundary, next_difficulty_from_window,
};
use xparq::crypto::{Address, BlockHash, Hash, TransactionHash};
use xparq::genesis::{GenesisError, genesis_hash, genesis_ledger};
use xparq::ledger::fork_choice::ForkChoice;
use xparq::ledger::{Chain, FINALITY_DEPTH, Ledger};
use xparq::qcash::recovery::{ROLLBACK_PROOF_VERSION, RollbackProofBundle};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceSummary {
    pub confirmed: Amount,
    pub available: Amount,
    pub pending: PendingBalance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountView {
    pub balance: Amount,
    pub unspendable: Amount,
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

impl Default for BalanceSummary {
    fn default() -> Self {
        Self {
            confirmed: Amount(0),
            available: Amount(0),
            pending: PendingBalance::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub ledger: Ledger,
    pub mempool: Mempool,
    pub storage: Storage,
    pub consensus: Consensus,
    pub cache: CoreCache,
    pub fork_choice: ForkChoice,
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
                fork_choice.insert_header(xparq::qcash::recovery::ChainHeader::new(
                    *height,
                    header.clone(),
                ))?;
            }
        }
        Ok(Self {
            ledger,
            mempool: Mempool::new(),
            storage,
            consensus,
            cache,
            fork_choice,
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
        })
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

        self.ledger = active_staged.ok_or(NodeError::MissingStagedLedger)?;
        self.snapshot_cache = None;
        if block.is_genesis() {
            self.genesis_accounts = self.ledger.accounts().clone();
            self.storage.save_genesis_accounts(&self.genesis_accounts)?;
        }
        self.mempool.remove_confirmed(&block)?;
        self.mark_rollback_issues_reconfirmed(&block)?;
        self.cache.insert_block(block.clone())?;
        for transaction in block.transactions() {
            if let SignedProtocolTransaction::Transfer(transaction) = transaction {
                if let Some(sender) = self.ledger.account(&transaction.transaction.from) {
                    self.cache.insert_account(sender.clone());
                }
                for output in &transaction.transaction.outputs {
                    if let Some(address) = output.to.address()
                        && let Some(receiver) = self.ledger.account(&address)
                    {
                        self.cache.insert_account(receiver.clone());
                    }
                }
            }
        }
        if let Some(miner) = self.ledger.account(&block.miner_address()) {
            self.cache.insert_account(miner.clone());
        }
        self.prune_finalized_state()?;
        self.storage.save_ledger(&self.ledger)?;
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
        let old_blocks: Vec<_> = self.ledger.chain.blocks.values().cloned().collect();
        let old_tip_hash = self.ledger.tip_hash();
        let best_tip = self
            .fork_choice
            .best_tip()
            .ok_or(NodeError::MissingBestTip)?
            .hash;
        let ancestor = self
            .common_ancestor(old_tip_hash, best_tip)
            .ok_or(NodeError::MissingCommonAncestor)?;
        if xparq::ledger::reorg_crosses_finality_boundary(&self.ledger, &self.fork_choice, ancestor)
        {
            return Err(xparq::ledger::LedgerError::FinalityViolation.into());
        }
        let winning_branch = self
            .fork_choice
            .branch_from_ancestor(ancestor, best_tip)
            .ok_or(NodeError::MissingForkBranch)?;
        let losing_headers =
            self.headers_to_tip(old_tip_hash.ok_or(NodeError::MissingActiveTip)?)?;
        let canonical_headers = self.headers_to_tip(best_tip)?;
        let proof_context = RollbackProofContext::new(losing_headers, canonical_headers, ancestor)?;
        self.storage.save_rollback_proof_context(&proof_context)?;

        self.ledger = self.ledger_for_branch_tip(best_tip)?;
        self.snapshot_cache = None;
        self.cache = CoreCache::from_ledger(&self.ledger)?;
        self.prune_finalized_state()?;
        self.storage.save_ledger(&self.ledger)?;

        let winning_hashes: std::collections::BTreeSet<_> = self
            .fork_choice
            .ancestor_hashes(best_tip)
            .into_iter()
            .collect();
        for old_block in old_blocks {
            let old_block_hash = old_block.hash()?;
            if winning_hashes.contains(&old_block_hash) {
                continue;
            }
            let old_block_height = old_block.height();
            for (transaction_index, transaction) in
                old_block.transactions().iter().cloned().enumerate()
            {
                let transaction_index = u32::try_from(transaction_index)
                    .map_err(|_| NodeError::TransactionIndexOverflow)?;
                let transaction_proof =
                    old_block.transaction_inclusion_proofs(transaction_index as usize)?;
                let mut issue = RollbackIssue::new(
                    old_block_height,
                    old_block_hash,
                    transaction_index,
                    transaction,
                    proof_context.id,
                    transaction_proof,
                    current_unix_timestamp(),
                )?;
                if let Some(existing) = self.storage.load_rollback_issue(&issue.id)? {
                    issue = existing;
                } else {
                    self.storage.save_rollback_issue(&issue)?;
                }
                self.retry_rollback_issue_record(&mut issue, false)?;
            }
        }

        // Keep the variable intentionally used for the common ancestor search, even when the
        // winning branch starts at genesis.
        let _ = winning_branch;
        self.reorgs_total = self.reorgs_total.saturating_add(1);
        Ok(())
    }

    pub fn rollback_issue(&self, id: &RollbackIssueId) -> Result<Option<RollbackIssue>, NodeError> {
        Ok(self.storage.load_rollback_issue(id)?)
    }

    pub fn rollback_proof_bundle(
        &self,
        issue: &RollbackIssue,
    ) -> Result<RollbackProofBundle, NodeError> {
        let context = self
            .storage
            .load_rollback_proof_context(&issue.proof_context_id)?
            .ok_or(NodeError::MissingRollbackProofContext)?;
        let current_canonical_headers =
            self.headers_to_tip(self.ledger.tip_hash().ok_or(NodeError::MissingActiveTip)?)?;
        let shared_count = context
            .losing_headers
            .iter()
            .zip(&current_canonical_headers)
            .take_while(|(left, right)| left == right)
            .count();
        if shared_count == 0
            || shared_count == context.losing_headers.len()
            || shared_count == current_canonical_headers.len()
        {
            return Err(NodeError::RollbackProofContextMismatch);
        }
        let canonical_headers = current_canonical_headers;
        let common_ancestor = canonical_headers[shared_count - 1].hash()?;
        let disconnected_block_header = context
            .losing_headers
            .iter()
            .find(|header| header.hash() == Ok(issue.disconnected_block_hash))
            .cloned()
            .ok_or(NodeError::MissingDisconnectedBlock)?;
        Ok(RollbackProofBundle {
            version: ROLLBACK_PROOF_VERSION,
            transaction: issue.transaction.clone(),
            disconnected_block_header,
            transaction_proof: issue.transaction_proof.clone(),
            losing_headers: context.losing_headers,
            canonical_headers,
            common_ancestor,
        })
    }

    pub fn rollback_issues_for_account(
        &self,
        address: &Address,
    ) -> Result<Vec<RollbackIssue>, NodeError> {
        Ok(self
            .storage
            .load_rollback_issues()?
            .into_iter()
            .filter(|issue| issue.affected_accounts.contains(address))
            .collect())
    }

    pub fn retry_rollback_issue(
        &mut self,
        id: &RollbackIssueId,
    ) -> Result<Option<RollbackIssue>, NodeError> {
        let Some(mut issue) = self.storage.load_rollback_issue(id)? else {
            return Ok(None);
        };
        if !issue.is_reconfirmed() {
            self.retry_rollback_issue_record(&mut issue, true)?;
        }
        Ok(Some(issue))
    }

    fn retry_rollback_issue_record(
        &mut self,
        issue: &mut RollbackIssue,
        verify_proof: bool,
    ) -> Result<(), NodeError> {
        if let Some((block_height, block_hash)) =
            self.canonical_transaction_location(issue.transaction_hash)?
        {
            issue.status = RollbackRecoveryStatus::Reconfirmed {
                block_height,
                block_hash,
            };
            issue.last_error = None;
            self.storage.save_rollback_issue(issue)?;
            return Ok(());
        }
        if verify_proof {
            let bundle = self.rollback_proof_bundle(issue)?;
            let verified = bundle.verify()?;
            if verified.transaction_hash != issue.transaction_hash
                || bundle.transaction != issue.transaction
                || verified.disconnected_block_hash != issue.disconnected_block_hash
                || Some(verified.canonical_tip) != self.ledger.tip_hash()
            {
                return Err(NodeError::RollbackIssueMismatch);
            }
        }
        issue.retry_attempts = issue.retry_attempts.saturating_add(1);
        match self.submit_protocol_transaction(issue.transaction.clone()) {
            Ok(_) | Err(NodeError::Mempool(MempoolError::DuplicateTransaction)) => {
                issue.status = RollbackRecoveryStatus::Requeued;
                issue.last_error = None;
            }
            Err(error) => {
                issue.status = RollbackRecoveryStatus::Conflict;
                issue.last_error = Some(error.to_string());
            }
        }
        self.storage.save_rollback_issue(issue)?;
        Ok(())
    }

    fn headers_to_tip(
        &self,
        tip: BlockHash,
    ) -> Result<Vec<xparq::qcash::recovery::ChainHeader>, NodeError> {
        let mut hashes = self.fork_choice.ancestor_hashes(tip);
        hashes.reverse();
        hashes
            .into_iter()
            .map(|hash| {
                self.fork_choice
                    .get(&hash)
                    .map(|node| {
                        xparq::qcash::recovery::ChainHeader::new(
                            node.block.height(),
                            node.block.header.clone(),
                        )
                    })
                    .ok_or(NodeError::MissingForkNode)
            })
            .collect()
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

    fn mark_rollback_issues_reconfirmed(&self, block: &Block) -> Result<(), NodeError> {
        let block_hash = block.hash()?;
        for transaction in block.transactions() {
            let transaction_hash = transaction.hash()?;
            for mut issue in self
                .storage
                .load_rollback_issues()?
                .into_iter()
                .filter(|issue| {
                    issue.transaction_hash == transaction_hash && !issue.is_reconfirmed()
                })
            {
                issue.status = RollbackRecoveryStatus::Reconfirmed {
                    block_height: block.height(),
                    block_hash,
                };
                issue.last_error = None;
                self.storage.save_rollback_issue(&issue)?;
            }
        }
        Ok(())
    }

    fn ledger_for_branch_tip(&self, tip: BlockHash) -> Result<Ledger, NodeError> {
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

        self.prune_finalized_state()?;

        Ok(())
    }

    fn prune_finalized_state(&mut self) -> Result<usize, NodeError> {
        let Some(tip_height) = self.ledger.tip_height() else {
            return Ok(0);
        };
        let finalized_height = Height(tip_height.0.saturating_sub(FINALITY_DEPTH as u64));
        let Some(finalized_block) = self.ledger.block(&finalized_height) else {
            return Ok(0);
        };
        let finalized_hash = finalized_block.hash()?;
        self.ledger.prune_finalized_rollback_state(finalized_height);
        Ok(self.fork_choice.prune_finalized(finalized_hash)?)
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
        let expected_difficulty = self.next_difficulty_after_branch_tip(parent.hash)?;
        let validation_consensus = self.consensus;
        validation_consensus.validate_next_block_with_tip(
            block,
            &parent.block,
            expected_difficulty,
        )?;
        Ok(())
    }

    pub fn mine_block(
        &mut self,
        miner_address: Address,
        timestamp: u64,
        max_attempts: u64,
        transaction_limit: usize,
    ) -> Result<MiningResult, NodeError> {
        self.mempool.evict_by_policy(timestamp)?;
        let difficulty = self.next_difficulty_at(timestamp)?;
        let result = mine_candidate_block(
            &self.mempool,
            &self.ledger,
            &self.consensus,
            miner_address,
            timestamp,
            MiningConfig {
                difficulty,
                start_nonce: 0,
                max_attempts,
                transaction_limit,
                min_fee_rate: self.mempool.dynamic_market_fee_rate(),
            },
        )?
        .ok_or(NodeError::MiningExhausted)?;

        self.apply_block(result.block.clone())?;
        Ok(result)
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

    fn expected_difficulty_after_tip_for_block(
        &self,
        tip_height: BlockHeight,
        block_timestamp: u64,
        block_height: BlockHeight,
    ) -> Result<u32, NodeError> {
        let _ = (block_timestamp, block_height);
        self.next_difficulty_after_tip(tip_height)
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

    fn expected_difficulty_after_branch_tip_for_block(
        &self,
        tip_hash: BlockHash,
        block_timestamp: u64,
        block_height: BlockHeight,
    ) -> Result<u32, NodeError> {
        let _ = (block_timestamp, block_height);
        self.next_difficulty_after_branch_tip(tip_hash)
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

    pub fn balance(&self, address: &Address) -> Option<Balance> {
        self.ledger.balance(address)
    }

    pub fn confirmed_balance(&self, address: &Address) -> Option<Balance> {
        self.ledger.confirmed_balance(address)
    }

    pub fn available_balance(&self, address: &Address) -> Option<Balance> {
        self.available_balance_with_depth(
            address,
            crate::runtime::params::CONFIRMATION_DEPTH as u64,
        )
    }

    pub fn available_balance_with_depth(
        &self,
        address: &Address,
        _finality_depth: u64,
    ) -> Option<Balance> {
        let tip_height = self.ledger.tip_height()?;
        self.ledger
            .xpq_utxos
            .available_balance(*address, tip_height)
            .ok()
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

    pub fn balance_summary(&self, address: &Address) -> Option<BalanceSummary> {
        Some(BalanceSummary {
            confirmed: self.confirmed_balance(address)?,
            available: self.available_balance(address)?,
            pending: self.pending_balance(address),
        })
    }

    pub fn account_view(&self, address: &Address) -> Option<AccountView> {
        self.ledger.account(address)?;
        let tip_height = self.ledger.tip_height()?;
        let balance = self
            .ledger
            .xpq_utxos
            .available_balance(*address, tip_height)
            .ok()?;
        let total = self.ledger.xpq_utxos.balance(*address).ok()?;
        Some(AccountView {
            balance,
            unspendable: Amount(total.0.saturating_sub(balance.0)),
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

// Legacy wrapper fixtures predate the xparq 0.2.20 block model.
#[cfg(all(test, any()))]
mod tests {
    use super::*;
    use crate::runtime::storage::Storage;
    use crate::test_support::BlockTestExt;
    use xparq::block::{Block, Height, Nonce};
    use xparq::consensus::supply::Amount;
    use xparq::consensus::{Consensus, ConsensusConfig};
    use xparq::crypto::{Hash, dual_address_from_public_keys, generate_keypair, sign};
    use xparq::ledger::Ledger;
    use xparq::state::Account;
    use xparq::transaction::{SignedTransaction, Transaction};

    fn address(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn mine_for_test(mut block: Block) -> Block {
        while Consensus::validate_proof_of_work_at_difficulty(&block, block.difficulty()).is_err() {
            block.header.nonce = Nonce(block.header.nonce.0.saturating_add(1));
        }
        block
    }

    #[test]
    fn invalid_state_block_does_not_enter_fork_choice() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let keypair = generate_keypair();
        let sender = dual_address_from_public_keys(&keypair.public_key, &keypair.public_key);
        let receiver = address(2);
        let mut genesis_accounts = BTreeMap::new();
        genesis_accounts.insert(sender, Account::new(sender, Amount(100)));
        genesis_accounts.insert(receiver, Account::new(receiver, Amount(0)));
        genesis_accounts.insert(address(9), Account::new(address(9), Amount(0)));
        let mut ledger =
            Ledger::from_accounts_and_chain(genesis_accounts.clone(), Chain::new()).unwrap();
        ledger.chain.insert_block(genesis.clone()).unwrap();
        let transaction = Transaction::new(sender, receiver, Amount(200), 0);
        let signature = sign(&keypair.secret_key, &transaction.signing_bytes().unwrap());
        let signed = SignedTransaction::new_authorized(
            transaction,
            keypair.public_key,
            signature,
            keypair.public_key,
            signature,
        );
        let block = mine_for_test(Block::new(
            Height(1),
            genesis.hash(),
            address(9),
            1_700_000_001,
            Nonce(0),
            vec![signed],
        ));
        let block_hash = block.hash().unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            genesis_accounts,
        );

        let error = node.apply_block(block).unwrap_err();

        assert!(matches!(error, NodeError::Ledger(_)));
        assert!(!node.fork_choice.contains(&block_hash));
        assert_eq!(node.tip_hash(), Some(genesis.hash().unwrap()));
    }

    #[test]
    fn reorgs_from_empty_genesis_accounts() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let mut active = Block::with_difficulty(
            Height(1),
            genesis.hash(),
            address(9),
            xparq::consensus::DIFFICULTY_START,
            1_700_000_001,
            Nonce(1),
            vec![],
        );
        let mut side = Block::with_difficulty(
            Height(1),
            genesis.hash(),
            address(8),
            xparq::consensus::DIFFICULTY_START,
            1_700_000_001,
            Nonce(2),
            vec![],
        );
        let genesis_accounts = BTreeMap::new();
        let mut ledger =
            Ledger::from_accounts_and_chain(genesis_accounts.clone(), Chain::new()).unwrap();
        ledger.chain.insert_block(genesis).unwrap();
        active = mine_for_test(active);
        side = mine_for_test(side);
        active.set_state_root(ledger.state_root_after_block(&active).unwrap());
        side.set_state_root(ledger.state_root_after_block(&side).unwrap());
        active = mine_for_test(active);
        side = mine_for_test(side);
        let mut side_ledger = ledger.clone();
        side_ledger
            .apply_block_at(side.clone(), side.timestamp())
            .unwrap();
        let mut side_child = Block::with_difficulty(
            Height(2),
            side.hash(),
            address(8),
            xparq::consensus::DIFFICULTY_START,
            1_700_000_002,
            Nonce(3),
            vec![],
        );
        side_child = mine_for_test(side_child);
        side_child.set_state_root(side_ledger.state_root_after_block(&side_child).unwrap());
        side_child = mine_for_test(side_child);
        let side_hash = side_child.hash().unwrap();
        let now = active.timestamp();
        ledger.apply_block_at(active, now).unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            genesis_accounts,
        );

        node.apply_block(side).unwrap();
        node.apply_block(side_child).unwrap();

        assert_eq!(node.tip_hash(), Some(side_hash));
        assert_eq!(
            node.balance(&address(8)),
            node.ledger.account(&address(8)).map(|a| a.balance)
        );
    }

    #[test]
    fn rejects_non_genesis_block_with_zero_state_root() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis.clone()).unwrap();
        let block = mine_for_test(Block::with_difficulty(
            Height(1),
            genesis.hash(),
            address(9),
            xparq::consensus::DIFFICULTY_START,
            1_700_000_001,
            Nonce(1),
            vec![],
        ));
        let block_hash = block.hash().unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            BTreeMap::new(),
        );

        let error = node.apply_block(block).unwrap_err();

        assert!(matches!(error, NodeError::Ledger(_)));
        assert!(!node.fork_choice.contains(&block_hash));
        assert_eq!(node.tip_hash(), Some(genesis.hash().unwrap()));
    }

    #[test]
    fn branch_difficulty_uses_wbda_weight_window_on_parent_branch() {
        let mut node = Node::temporary(
            Ledger::new(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
        )
        .unwrap();
        let genesis = xparq::genesis::genesis_block().unwrap();
        let mut previous_hash = node.fork_choice.insert_block(genesis).unwrap();

        let blocks = WBDA_WINDOW as u64;
        for height in 1..=blocks {
            let difficulty = node
                .next_difficulty_after_branch_tip(previous_hash)
                .unwrap();
            let block = mine_for_test(Block::with_difficulty(
                Height(height),
                previous_hash,
                address(9),
                difficulty,
                1_700_000_000,
                Nonce(height),
                vec![],
            ));
            previous_hash = node.fork_choice.insert_block(block).unwrap();
        }

        let expected = node
            .next_difficulty_after_branch_tip(previous_hash)
            .unwrap();
        assert_eq!(expected, 2);

        let mut candidate = Block::with_difficulty(
            Height(blocks + 1),
            previous_hash,
            address(9),
            expected,
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        candidate = mine_for_test(candidate);
        node.validate_block_for_known_parent(&candidate).unwrap();
    }

    #[test]
    fn indexes_stored_side_blocks_into_fork_choice() {
        let genesis = mine_for_test(Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        ));
        let active = mine_for_test(Block::with_difficulty(
            Height(1),
            genesis.hash(),
            address(9),
            1,
            1_700_000_001,
            Nonce(1),
            vec![],
        ));
        let side = mine_for_test(Block::with_difficulty(
            Height(1),
            genesis.hash(),
            address(8),
            1,
            1_700_000_002,
            Nonce(2),
            vec![],
        ));
        let side_hash = side.hash().unwrap();
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis).unwrap();
        ledger.chain.insert_block(active).unwrap();
        let storage = Storage::temporary().unwrap();
        storage.save_ledger(&ledger).unwrap();
        storage.save_side_block(&side).unwrap();
        let mut node = Node::new(
            ledger,
            storage,
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
        );

        node.index_stored_blocks().unwrap();

        assert!(node.fork_choice.contains(&side_hash));
    }

    #[test]
    fn caches_orphan_block_until_parent_arrives() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let mut parent = Block::with_difficulty(
            Height(1),
            genesis.hash(),
            address(9),
            1,
            1_700_000_001,
            Nonce(1),
            vec![],
        );
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis.clone()).unwrap();
        parent = mine_for_test(parent);
        parent.set_state_root(ledger.state_root_after_block(&parent).unwrap());
        parent = mine_for_test(parent);
        let mut child_ledger = ledger.clone();
        child_ledger.chain.insert_block(parent.clone()).unwrap();

        let mut child = Block::with_difficulty(
            Height(2),
            parent.hash(),
            address(9),
            1,
            1_700_000_002,
            Nonce(2),
            vec![],
        );
        child.set_state_root(child_ledger.protocol_state_root().unwrap());
        child = mine_for_test(child);
        let child_hash = child.hash().unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            BTreeMap::new(),
        );

        node.apply_block(child).unwrap();

        assert_eq!(node.orphan_blocks.len(), 1);
        assert!(!node.fork_choice.contains(&child_hash));
        assert_eq!(node.tip_hash(), Some(genesis.hash().unwrap()));

        let parent_hash = parent.hash().unwrap();
        node.apply_block(parent).unwrap();

        assert!(node.orphan_blocks.is_empty());
        assert!(node.fork_choice.contains(&parent_hash));
        assert_eq!(node.tip_height(), Some(Height(1)));
    }

    #[test]
    fn prunes_expired_orphan_blocks() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let missing_parent_hash = BlockHash([7; HASH_SIZE]);
        let child = Block::with_difficulty(
            Height(1),
            missing_parent_hash,
            address(9),
            1,
            1_700_000_001,
            Nonce(1),
            vec![],
        );
        let child_hash = child.hash().unwrap();
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis).unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            BTreeMap::new(),
        );

        node.apply_block(child).unwrap();
        node.orphan_blocks.get_mut(&child_hash).unwrap().received_at = 1;
        node.prune_expired_orphans(ORPHAN_BLOCK_TTL_SECS + 2);

        assert!(node.orphan_blocks.is_empty());
        assert!(node.orphan_children_by_parent.is_empty());
    }

    #[test]
    fn queues_missing_parent_request_once_for_orphans() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let missing_parent_hash = BlockHash([7; HASH_SIZE]);
        let first = Block::with_difficulty(
            Height(1),
            missing_parent_hash,
            address(9),
            1,
            1_700_000_001,
            Nonce(1),
            vec![],
        );
        let second = Block::with_difficulty(
            Height(1),
            missing_parent_hash,
            address(8),
            1,
            1_700_000_002,
            Nonce(2),
            vec![],
        );
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis).unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            BTreeMap::new(),
        );

        node.apply_block(first).unwrap();
        node.apply_block(second).unwrap();

        assert_eq!(
            node.drain_missing_parent_requests(),
            vec![missing_parent_hash]
        );
        assert!(node.drain_missing_parent_requests().is_empty());
    }

    #[test]
    fn retries_missing_parent_request_after_cooldown() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let missing_parent_hash = BlockHash([7; HASH_SIZE]);
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis).unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            BTreeMap::new(),
        );

        node.queue_missing_parent_request_at(missing_parent_hash, 10);
        assert!(node.drain_missing_parent_requests_at(9).is_empty());
        assert_eq!(
            node.drain_missing_parent_requests_at(10),
            vec![missing_parent_hash]
        );

        node.retry_missing_parent_request(missing_parent_hash);
        assert!(
            node.drain_missing_parent_requests_at(current_unix_timestamp())
                .is_empty()
        );
    }

    #[test]
    fn ignores_orphan_blocks_too_far_ahead_of_tip() {
        let genesis = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let far_orphan = Block::with_difficulty(
            Height(MAX_ORPHAN_HEIGHT_DISTANCE + 1),
            BlockHash([7; HASH_SIZE]),
            address(9),
            1,
            1_700_000_001,
            Nonce(1),
            vec![],
        );
        let mut ledger = Ledger::new();
        ledger.chain.insert_block(genesis).unwrap();
        let mut node = Node::with_genesis_accounts(
            ledger,
            Storage::temporary().unwrap(),
            Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
            BTreeMap::new(),
        );

        node.apply_block(far_orphan).unwrap();

        assert!(node.orphan_blocks.is_empty());
        assert!(node.orphan_children_by_parent.is_empty());
    }
}
