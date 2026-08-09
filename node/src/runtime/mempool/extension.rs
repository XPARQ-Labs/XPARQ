use super::MempoolError;
use crate::runtime::params::{
    DEFAULT_MARKET_FEE, DEFAULT_MIN_RELAY_FEE, DYNAMIC_MARKET_FEE_MAX_MULTIPLIER,
    LOW_FEE_EXPIRY_SECS, MAX_MEMPOOL_BYTES, MAX_MEMPOOL_TXS, MEMPOOL_EXPIRY_SECS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use xparq::block::{Block, BlockHeight, MAX_BLOCK_SIZE, MAX_BLOCK_WEIGHT};
use xparq::crypto::TransactionHash;
use xparq::ledger::Ledger;
use xparq::state::{QCashCoinId, XpqCoinId};
use xparq::transaction::{QCashTransactionKind, SignedProtocolTransaction, TransactionFamily};

/// Ordered pool for every protocol transaction family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mempool {
    transactions: BTreeMap<TransactionHash, SignedProtocolTransaction>,
    insertion_order: Vec<TransactionHash>,
    reserved_qcash_coins: BTreeMap<QCashCoinId, TransactionHash>,
    reserved_xpq_coins: BTreeMap<XpqCoinId, TransactionHash>,
    inserted_at: BTreeMap<TransactionHash, u64>,
    total_bytes: usize,
    config: MempoolConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MempoolConfig {
    pub max_transactions: usize,
    pub max_bytes: usize,
    pub transaction_ttl_secs: u64,
    pub low_fee_ttl_secs: u64,
    pub min_relay_fee: u64,
    pub market_fee: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeeMarketSnapshot {
    pub min_relay_fee_rate: u64,
    pub configured_market_fee_rate: u64,
    pub recommended_fee_rate: u64,
    pub pressure_bps: u64,
    pub transaction_count: usize,
    pub total_bytes: usize,
    pub max_transactions: usize,
    pub max_bytes: usize,
    pub next_block_clearing_fee_rate: u64,
    pub median_fee_rate: u64,
    pub p75_fee_rate: u64,
    pub p90_fee_rate: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: MAX_MEMPOOL_TXS,
            max_bytes: MAX_MEMPOOL_BYTES,
            transaction_ttl_secs: MEMPOOL_EXPIRY_SECS,
            low_fee_ttl_secs: LOW_FEE_EXPIRY_SECS,
            min_relay_fee: DEFAULT_MIN_RELAY_FEE,
            market_fee: DEFAULT_MARKET_FEE,
        }
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn config(&self) -> MempoolConfig {
        self.config
    }

    pub fn insert_validated(
        &mut self,
        ledger: &Ledger,
        transaction: SignedProtocolTransaction,
    ) -> Result<TransactionHash, MempoolError> {
        let transaction_size = transaction
            .to_bytes()
            .map_err(MempoolError::Serialization)?
            .len();
        if transaction_size > self.config.max_bytes {
            return Err(MempoolError::MempoolFull);
        }
        let hash = transaction.hash().map_err(MempoolError::Serialization)?;
        if self.transactions.contains_key(&hash) {
            return Err(MempoolError::DuplicateTransaction);
        }
        self.evict_for_capacity(&transaction, transaction_size)?;
        let qcash_coin_ids = redeem_coin_ids(&transaction);
        if qcash_coin_ids
            .iter()
            .any(|coin_id| self.reserved_qcash_coins.contains_key(coin_id))
        {
            return Err(MempoolError::CashCoinReserved);
        }
        let xpq_coin_ids = xpq_input_coin_ids(&transaction);
        if xpq_coin_ids
            .iter()
            .any(|coin_id| self.reserved_xpq_coins.contains_key(coin_id))
        {
            return Err(MempoolError::DuplicateTransaction);
        }

        let height = ledger
            .tip_height()
            .map(|height| xparq::block::Height(height.0.saturating_add(1)))
            .unwrap_or(xparq::block::Height(0));
        let mut staged = ledger.clone();
        for pending_hash in &self.insertion_order {
            if let Some(pending_transaction) = self.transactions.get(pending_hash) {
                apply_extension(&mut staged, pending_transaction, height)?;
            }
        }
        apply_extension(&mut staged, &transaction, height)?;

        for coin_id in qcash_coin_ids {
            self.reserved_qcash_coins.insert(coin_id, hash);
        }
        for coin_id in xpq_coin_ids {
            self.reserved_xpq_coins.insert(coin_id, hash);
        }
        self.transactions.insert(hash, transaction);
        self.insertion_order.push(hash);
        self.inserted_at.insert(hash, current_unix_timestamp());
        self.total_bytes = self.total_bytes.saturating_add(transaction_size);
        Ok(hash)
    }

    fn evict_for_capacity(
        &mut self,
        incoming: &SignedProtocolTransaction,
        incoming_size: usize,
    ) -> Result<(), MempoolError> {
        let incoming_rate = miner_bounty_rate(incoming)?;
        while self.transactions.len() >= self.config.max_transactions
            || self.total_bytes.saturating_add(incoming_size) > self.config.max_bytes
        {
            let Some((victim_hash, victim_rate, _inserted_at)) = self.lowest_fee_candidate() else {
                return Err(MempoolError::MempoolFull);
            };
            if incoming_rate <= victim_rate {
                return Err(MempoolError::FeeTooLow);
            }
            self.remove(&victim_hash)?;
        }
        Ok(())
    }

    fn lowest_fee_candidate(&self) -> Option<(TransactionHash, u64, u64)> {
        self.transactions
            .iter()
            .filter_map(|(hash, transaction)| {
                let rate = miner_bounty_rate(transaction).ok()?;
                let inserted_at = self.inserted_at.get(hash).copied().unwrap_or(0);
                Some((*hash, rate, inserted_at))
            })
            .min_by(|left, right| {
                left.1
                    .cmp(&right.1)
                    .then_with(|| left.2.cmp(&right.2))
                    .then_with(|| left.0.cmp(&right.0))
            })
    }

    pub fn contains(&self, hash: &TransactionHash) -> bool {
        self.transactions.contains_key(hash)
    }

    pub fn get(&self, hash: &TransactionHash) -> Option<&SignedProtocolTransaction> {
        self.transactions.get(hash)
    }

    #[cfg(test)]
    pub(crate) fn insert_for_compact_test(
        &mut self,
        transaction: SignedProtocolTransaction,
    ) -> Result<(), xparq::error::CodecError> {
        self.transactions.insert(transaction.hash()?, transaction);
        Ok(())
    }

    pub fn transactions(&self) -> impl Iterator<Item = &SignedProtocolTransaction> {
        self.transactions.values()
    }

    pub fn transactions_for_family(
        &self,
        family: TransactionFamily,
    ) -> impl Iterator<Item = &SignedProtocolTransaction> {
        self.transactions
            .values()
            .filter(move |transaction| transaction.family() == family)
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn remove(
        &mut self,
        hash: &TransactionHash,
    ) -> Result<Option<SignedProtocolTransaction>, MempoolError> {
        let Some(transaction) = self.transactions.remove(hash) else {
            return Ok(None);
        };
        self.inserted_at.remove(hash);
        self.total_bytes = self.total_bytes.saturating_sub(
            transaction
                .to_bytes()
                .map_err(MempoolError::Serialization)?
                .len(),
        );
        self.insertion_order.retain(|candidate| candidate != hash);
        for coin_id in redeem_coin_ids(&transaction) {
            if self.reserved_qcash_coins.get(&coin_id) == Some(hash) {
                self.reserved_qcash_coins.remove(&coin_id);
            }
        }
        for coin_id in xpq_input_coin_ids(&transaction) {
            if self.reserved_xpq_coins.get(&coin_id) == Some(hash) {
                self.reserved_xpq_coins.remove(&coin_id);
            }
        }
        Ok(Some(transaction))
    }

    pub fn evict_by_policy(&mut self, now: u64) -> Result<usize, MempoolError> {
        if self.config.transaction_ttl_secs == 0 {
            return Ok(0);
        }
        let mut evicted = Vec::new();
        for hash in self.transactions.keys() {
            let inserted_at = self.inserted_at.get(hash).copied().unwrap_or(now);
            let ttl = self.config.transaction_ttl_secs;
            if inserted_at.saturating_add(ttl) <= now {
                evicted.push(*hash);
            }
        }
        let removed = evicted.len();
        for hash in evicted {
            self.remove(&hash)?;
        }
        Ok(removed)
    }

    pub fn mempool_pressure_bps(&self) -> u64 {
        occupancy_bps(self.total_bytes, self.config.max_bytes).max(occupancy_bps(
            self.transactions.len(),
            self.config.max_transactions,
        ))
    }

    pub fn dynamic_market_fee_rate(&self) -> u64 {
        self.fee_market_snapshot().recommended_fee_rate
    }

    pub fn fee_market_snapshot(&self) -> FeeMarketSnapshot {
        let base_rate = self.config.market_fee.max(self.config.min_relay_fee);
        let pressure_bps = self.mempool_pressure_bps();
        let premium = base_rate
            .saturating_mul(DYNAMIC_MARKET_FEE_MAX_MULTIPLIER)
            .saturating_mul(pressure_bps)
            / 10_000;
        let pressure_rate = base_rate.saturating_add(premium);
        let mut entries = self
            .transactions
            .values()
            .filter_map(|transaction| {
                let virtual_size = transaction.virtual_size().ok()?;
                let rate = miner_bounty_rate(transaction).ok()?;
                Some((rate, virtual_size))
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));

        let next_block_clearing_fee_rate =
            weighted_clearing_rate(&entries, MAX_BLOCK_WEIGHT).unwrap_or(base_rate);
        let median_fee_rate = weighted_percentile_rate(&entries, 50).unwrap_or(base_rate);
        let p75_fee_rate = weighted_percentile_rate(&entries, 75).unwrap_or(base_rate);
        let p90_fee_rate = weighted_percentile_rate(&entries, 90).unwrap_or(base_rate);
        let recommended_fee_rate = [
            base_rate,
            pressure_rate,
            next_block_clearing_fee_rate,
            p75_fee_rate,
        ]
        .into_iter()
        .max()
        .unwrap_or(base_rate);

        FeeMarketSnapshot {
            min_relay_fee_rate: self.config.min_relay_fee,
            configured_market_fee_rate: self.config.market_fee,
            recommended_fee_rate,
            pressure_bps,
            transaction_count: self.transactions.len(),
            total_bytes: self.total_bytes,
            max_transactions: self.config.max_transactions,
            max_bytes: self.config.max_bytes,
            next_block_clearing_fee_rate,
            median_fee_rate,
            p75_fee_rate,
            p90_fee_rate,
        }
    }

    pub fn select_for_block(
        &self,
        ledger: &Ledger,
        height: BlockHeight,
        _block_timestamp: u64,
        limit: usize,
        min_bounty_rate: u64,
    ) -> Result<Vec<SignedProtocolTransaction>, MempoolError> {
        let mut ordered = self.transactions.values().cloned().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            let left_rate = miner_bounty_rate(left).unwrap_or(0);
            let right_rate = miner_bounty_rate(right).unwrap_or(0);
            right_rate
                .cmp(&left_rate)
                .then_with(|| left.signer().cmp(&right.signer()))
                .then_with(|| left.hash().ok().cmp(&right.hash().ok()))
        });
        let mut staged = ledger.clone();
        let mut candidates = Vec::new();
        let mut remaining = ordered;
        while !remaining.is_empty() && candidates.len() < limit {
            let mut progressed = false;
            let mut deferred = Vec::new();
            for transaction in remaining {
                if candidates.len() == limit {
                    deferred.push(transaction);
                    continue;
                }
                if miner_bounty_rate(&transaction)? < min_bounty_rate
                    && miner_bounty(&transaction) > 0
                {
                    continue;
                }
                if transaction.validity().validate_at(height).is_err() {
                    continue;
                }
                if apply_extension(&mut staged, &transaction, height).is_err() {
                    deferred.push(transaction);
                    continue;
                }
                candidates.push(transaction);
                progressed = true;
            }
            if !progressed {
                break;
            }
            remaining = deferred;
        }
        Ok(candidates)
    }

    pub fn append_selected_to_block(
        &self,
        ledger: &Ledger,
        block: &mut Block,
        transaction_limit: usize,
        min_fee_rate: u64,
    ) -> Result<(), MempoolError> {
        let remaining = transaction_limit.saturating_sub(block.transaction_count());
        for transaction in
            self.select_for_block(ledger, block.height(), 0, remaining, min_fee_rate)?
        {
            block.body.transactions.push(transaction);
            refresh_block_fees_and_commitments(block)?;
            if block
                .serialized_size()
                .map_err(MempoolError::Serialization)?
                > MAX_BLOCK_SIZE
                || block.weight().map_err(MempoolError::Serialization)? > MAX_BLOCK_WEIGHT
            {
                block.body.transactions.pop();
                refresh_block_fees_and_commitments(block)?;
            }
        }
        refresh_block_fees_and_commitments(block)?;
        Ok(())
    }

    pub fn remove_confirmed(&mut self, block: &Block) -> Result<(), MempoolError> {
        let hashes = block
            .transactions()
            .iter()
            .map(|tx| tx.hash())
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(MempoolError::Serialization)?;
        for hash in hashes {
            self.remove(&hash)?;
        }
        Ok(())
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn occupancy_bps(used: usize, capacity: usize) -> u64 {
    if capacity == 0 {
        return 10_000;
    }
    ((used as u128).saturating_mul(10_000) / capacity as u128).min(10_000) as u64
}

fn weighted_clearing_rate(entries: &[(u64, usize)], target_weight: usize) -> Option<u64> {
    if entries.is_empty() {
        return None;
    }
    let mut accumulated = 0usize;
    let mut last_rate = entries[0].0;
    for (rate, virtual_size) in entries {
        accumulated = accumulated.saturating_add(*virtual_size);
        last_rate = *rate;
        if accumulated >= target_weight {
            return Some(*rate);
        }
    }
    Some(last_rate)
}

fn weighted_percentile_rate(entries: &[(u64, usize)], percentile: u64) -> Option<u64> {
    if entries.is_empty() {
        return None;
    }
    let total = entries
        .iter()
        .fold(0usize, |total, (_, size)| total.saturating_add(*size));
    if total == 0 {
        return Some(entries[0].0);
    }
    let target = ((total as u128)
        .saturating_mul(percentile as u128)
        .saturating_add(99)
        / 100)
        .max(1) as usize;
    let mut accumulated = 0usize;
    for (rate, virtual_size) in entries {
        accumulated = accumulated.saturating_add(*virtual_size);
        if accumulated >= target {
            return Some(*rate);
        }
    }
    entries.last().map(|(rate, _)| *rate)
}

fn fee_rate(fee: u64, virtual_size: usize) -> u64 {
    if virtual_size == 0 {
        return u64::MAX;
    }
    fee.saturating_mul(crate::runtime::params::FEE_RATE_UNIT_BYTES as u64) / virtual_size as u64
}

fn miner_bounty_rate(transaction: &SignedProtocolTransaction) -> Result<u64, MempoolError> {
    let virtual_size = transaction
        .virtual_size()
        .map_err(MempoolError::Serialization)?;
    Ok(fee_rate(miner_bounty(transaction), virtual_size))
}

fn miner_bounty(transaction: &SignedProtocolTransaction) -> u64 {
    match transaction {
        SignedProtocolTransaction::Transfer(transaction) => transaction
            .transaction
            .outputs
            .iter()
            .filter(|output| output.to == xparq::transaction::OutputTarget::BlockMiner)
            .fold(0_u64, |sum, output| sum.saturating_add(output.amount.0)),
        SignedProtocolTransaction::QCash(transaction) => transaction.transaction.miner_bounty().0,
    }
}

fn refresh_block_fees_and_commitments(block: &mut Block) -> Result<(), MempoolError> {
    block
        .refresh_commitments()
        .map_err(MempoolError::Serialization)?;
    Ok(())
}

fn apply_extension(
    staged: &mut Ledger,
    transaction: &SignedProtocolTransaction,
    height: BlockHeight,
) -> Result<(), MempoolError> {
    match transaction {
        SignedProtocolTransaction::Transfer(tx) => {
            staged.apply_signed_transaction_at(tx, height)?;
        }
        SignedProtocolTransaction::QCash(tx) => {
            staged.apply_signed_qcash_transaction(tx, height)?;
        }
    }
    Ok(())
}

fn xpq_input_coin_ids(transaction: &SignedProtocolTransaction) -> Vec<XpqCoinId> {
    match transaction {
        SignedProtocolTransaction::Transfer(tx) => tx.transaction.inputs.clone(),
        SignedProtocolTransaction::QCash(tx) => match &tx.transaction.kind {
            QCashTransactionKind::Withdraw { inputs, .. } => inputs.clone(),
            _ => Vec::new(),
        },
    }
}

fn redeem_coin_ids(transaction: &SignedProtocolTransaction) -> Vec<QCashCoinId> {
    match transaction {
        SignedProtocolTransaction::QCash(tx) => match &tx.transaction.kind {
            QCashTransactionKind::Redeem { metadata, .. } => metadata
                .inputs
                .iter()
                .map(|input| QCashCoinId(input.coin_id))
                .collect(),
            QCashTransactionKind::Withdraw { .. } => Vec::new(),
        },
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod miner_fee_output_tests {
    use super::*;
    use xparq::consensus::supply::Amount;
    use xparq::crypto::{Address, dual_address_from_public_keys, generate_keypair, sign};
    use xparq::transaction::{OutputTarget, SignedTransfer, Transfer, TransferOutput};

    #[test]
    fn payment_with_miner_fee_output_is_selected_by_fee_rate() {
        let owner = generate_keypair();
        let authorization = generate_keypair();
        let sender = dual_address_from_public_keys(&owner.public_key, &authorization.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, authorization.public_key, Amount(100_000))
            .unwrap();

        let sign_transfer = |transaction: Transfer| {
            let payload = transaction.signing_bytes().unwrap();
            SignedTransfer::new_authorized(
                transaction,
                owner.public_key,
                sign(&owner.secret_key, &payload),
                authorization.public_key,
                sign(&authorization.secret_key, &payload),
            )
        };
        let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
        let payment = sign_transfer(Transfer::from_outputs(
            sender,
            vec![input],
            vec![
                TransferOutput::new(Address([7; 20]), Amount(10)),
                TransferOutput::new(OutputTarget::BlockMiner, Amount(10_000)),
                TransferOutput::new(sender, Amount(89_990)),
            ],
        ));

        let mut mempool = Mempool::new();
        mempool.insert_validated(&ledger, payment.into()).unwrap();

        let selected = mempool
            .select_for_block(&ledger, xparq::block::Height(0), 0, 1, 1)
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(miner_bounty(&selected[0]), 10_000);
    }
}
