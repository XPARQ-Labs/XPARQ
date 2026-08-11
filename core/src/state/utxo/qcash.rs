//! Consensus UTXO set for QCash bearer outputs.

use crate::block::{BlockHeight, Height};
use crate::consensus::supply::Amount;
use crate::crypto::{Address, BlockHash, HASH_SIZE, Hash, TransactionHash};
use crate::qcash::{
    QCashDenomination, QCashError, QCashRedeemMetadata, QCashWithdrawalMetadata,
    QCashWithdrawalOutput, qcash_coin_id_bytes, qcash_redeem_key_commitment,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use super::proof::{QCashSparseStateTree, QCashStateProof};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct QCashCoinId(pub [u8; HASH_SIZE]);

/// Canonical origin of one QCash output.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct QCashOutPoint {
    pub transaction_hash: TransactionHash,
    pub output_index: u32,
}

impl QCashCoinId {
    pub fn derive(
        withdraw_tx_hash: TransactionHash,
        output: &QCashWithdrawalOutput,
    ) -> Result<Self, QCashError> {
        Ok(Self(qcash_coin_id_bytes(withdraw_tx_hash, output)?))
    }

    /// Nine uppercase hexadecimal characters for human-facing file names.
    pub fn short_id(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut value = String::with_capacity(9);
        for byte in self.0.iter().take(5) {
            value.push(HEX[(byte >> 4) as usize] as char);
            if value.len() == 9 {
                break;
            }
            value.push(HEX[(byte & 0x0f) as usize] as char);
            if value.len() == 9 {
                break;
            }
        }
        value
    }

    pub fn file_name(&self, denomination: QCashDenomination) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut full_id = String::with_capacity(self.0.len() * 2);
        for byte in self.0 {
            full_id.push(HEX[(byte >> 4) as usize] as char);
            full_id.push(HEX[(byte & 0x0f) as usize] as char);
        }
        format!("{}XPQ_{full_id}.QCash", denomination.xpq())
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum QCashRedeemability {
    Pending,
    Redeemable,
}

/// One individually tracked QCash coin.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct QCashUtxo {
    pub id: QCashCoinId,
    pub outpoint: QCashOutPoint,
    pub withdrawer: Address,
    pub denomination: QCashDenomination,
    pub redeem_key_commitment: [u8; 32],
    pub issued_height: BlockHeight,
}

impl QCashUtxo {
    pub fn redeemability_at(&self, height: BlockHeight) -> QCashRedeemability {
        if is_redeemable_at(self, height) {
            QCashRedeemability::Redeemable
        } else {
            QCashRedeemability::Pending
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct QCashBlockJournal {
    pub block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub previous_journal_tip: Option<BlockHash>,
    pub issued_coin_ids: Vec<QCashCoinId>,
    pub redeemed_utxos: Vec<QCashUtxo>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default,
)]
pub struct QCashUtxoSet {
    coins: BTreeMap<QCashCoinId, QCashUtxo>,
    journals: BTreeMap<BlockHash, QCashBlockJournal>,
    active_journal_tip: Option<BlockHash>,
}

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QCashJournalState {
    journals: BTreeMap<BlockHash, QCashBlockJournal>,
    active_journal_tip: Option<BlockHash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QCashUtxoError {
    InvalidMetadata,
    WrongOperation,
    StateOverflow,
    UnknownCoin,
    DuplicateCoin,
    DenominationMismatch,
    CoinIdCollision,
    InvalidCoinProof,
    CoinDerivation(crate::qcash::QCashError),
    CoinNotRedeemable,
    MissingBlockJournal,
    NonTipRollback,
}

impl fmt::Display for QCashUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata => f.write_str("invalid QCash metadata"),
            Self::WrongOperation => {
                f.write_str("QCash metadata operation does not match state operation")
            }
            Self::StateOverflow => f.write_str("QCash UTXO value overflow"),
            Self::UnknownCoin => f.write_str("QCash output is unknown or already redeemed"),
            Self::DuplicateCoin => f.write_str("QCash coin is repeated in the operation"),
            Self::DenominationMismatch => {
                f.write_str("QCash coin denominations do not match metadata")
            }
            Self::CoinIdCollision => f.write_str("derived QCash coin ID already exists"),
            Self::InvalidCoinProof => f.write_str("QCash coin proof does not match issued output"),
            Self::CoinDerivation(error) => write!(f, "failed to derive QCash coin ID: {error}"),
            Self::CoinNotRedeemable => {
                f.write_str("QCash coin has not completed its minimum off-chain block delay")
            }
            Self::MissingBlockJournal => f.write_str("QCash block journal was not found"),
            Self::NonTipRollback => f.write_str("QCash rollback must disconnect the journal tip"),
        }
    }
}

impl Error for QCashUtxoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CoinDerivation(error) => Some(error),
            _ => None,
        }
    }
}

impl QCashUtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn coin(&self, id: QCashCoinId) -> Option<&QCashUtxo> {
        self.coins.get(&id)
    }

    pub fn coins(&self) -> impl Iterator<Item = &QCashUtxo> {
        self.coins.values()
    }

    #[doc(hidden)]
    pub fn persistence_journal_state(&self) -> QCashJournalState {
        QCashJournalState {
            journals: self.journals.clone(),
            active_journal_tip: self.active_journal_tip,
        }
    }

    #[doc(hidden)]
    pub fn apply_persistence_diff(
        &mut self,
        removed: &[QCashCoinId],
        upserted: impl IntoIterator<Item = QCashUtxo>,
        journal_state: QCashJournalState,
    ) {
        for id in removed {
            self.coins.remove(id);
        }
        for coin in upserted {
            self.coins.insert(coin.id, coin);
        }
        self.journals = journal_state.journals;
        self.active_journal_tip = journal_state.active_journal_tip;
    }

    pub fn journal(&self, block_hash: BlockHash) -> Option<&QCashBlockJournal> {
        self.journals.get(&block_hash)
    }

    /// Consensus commitment excluding local rollback journals and event counters.
    pub fn consensus_root(&self) -> Result<Hash, crate::error::CodecError> {
        Ok(QCashSparseStateTree::from_coins(&self.coins)?.root())
    }

    pub fn create_state_proof(
        &self,
        coin_id: QCashCoinId,
    ) -> Result<QCashStateProof, crate::error::CodecError> {
        QCashSparseStateTree::from_coins(&self.coins)?
            .create_proof(coin_id, self.coins.get(&coin_id).cloned())
    }

    pub fn redeemable_utxos_at(&self, height: BlockHeight) -> impl Iterator<Item = &QCashUtxo> {
        self.coins
            .values()
            .filter(move |coin| is_redeemable_at(coin, height))
    }

    pub fn redeemable_utxos(&self) -> impl Iterator<Item = &QCashUtxo> {
        self.redeemable_utxos_at(Height(u64::MAX))
    }

    pub fn utxos(&self) -> impl Iterator<Item = &QCashUtxo> {
        self.coins.values()
    }

    pub fn redeemable_balance(&self) -> Result<Amount, QCashUtxoError> {
        self.redeemable_utxos().try_fold(Amount(0), |total, coin| {
            total
                .0
                .checked_add(coin.denomination.amount().0)
                .map(Amount)
                .ok_or(QCashUtxoError::StateOverflow)
        })
    }

    pub fn redeemable_balance_at(&self, height: BlockHeight) -> Result<Amount, QCashUtxoError> {
        self.redeemable_utxos_at(height)
            .try_fold(Amount(0), |total, coin| {
                total
                    .0
                    .checked_add(coin.denomination.amount().0)
                    .map(Amount)
                    .ok_or(QCashUtxoError::StateOverflow)
            })
    }

    pub fn total_value(&self) -> Result<Amount, QCashUtxoError> {
        self.utxos().try_fold(Amount(0), |total, coin| {
            total
                .0
                .checked_add(coin.denomination.amount().0)
                .map(Amount)
                .ok_or(QCashUtxoError::StateOverflow)
        })
    }

    /// Issues and stores every coin represented by withdraw metadata.
    pub fn apply_withdraw(
        &mut self,
        withdrawer: Address,
        withdraw_tx_hash: TransactionHash,
        metadata: &QCashWithdrawalMetadata,
        height: BlockHeight,
    ) -> Result<Vec<QCashCoinId>, QCashUtxoError> {
        metadata
            .validate()
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let mut pending: Vec<(QCashCoinId, &QCashWithdrawalOutput)> =
            Vec::with_capacity(metadata.outputs.len());
        for output in &metadata.outputs {
            let id = QCashCoinId::derive(withdraw_tx_hash, output)
                .map_err(QCashUtxoError::CoinDerivation)?;
            if self.coins.contains_key(&id)
                || pending.iter().any(|(pending_id, _)| *pending_id == id)
            {
                return Err(QCashUtxoError::CoinIdCollision);
            }
            pending.push((id, output));
        }

        let mut ids = Vec::with_capacity(pending.len());
        for (id, output) in pending {
            self.coins.insert(
                id,
                QCashUtxo {
                    id,
                    outpoint: QCashOutPoint {
                        transaction_hash: withdraw_tx_hash,
                        output_index: output.coin_index,
                    },
                    withdrawer,
                    denomination: output.denomination,
                    redeem_key_commitment: output.redeem_key_commitment,
                    issued_height: height,
                },
            );
            ids.push(id);
        }
        Ok(ids)
    }

    /// Verifies bearer secrets and atomically redeems explicit redeem inputs.
    pub fn apply_redeem(
        &mut self,
        metadata: &QCashRedeemMetadata,
        recipient: Address,
        height: BlockHeight,
        transaction_commitment: [u8; 32],
    ) -> Result<Amount, QCashUtxoError> {
        metadata
            .validate_authorizations_for_transaction(recipient, transaction_commitment)
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let (ids, amount) = self.validate_redeem(metadata, height)?;
        for id in ids {
            self.coins.remove(&id).ok_or(QCashUtxoError::UnknownCoin)?;
        }
        Ok(amount)
    }

    pub fn apply_withdraw_in_block(
        &mut self,
        block_hash: BlockHash,
        height: BlockHeight,
        withdrawer: Address,
        withdraw_tx_hash: TransactionHash,
        metadata: &QCashWithdrawalMetadata,
    ) -> Result<Vec<QCashCoinId>, QCashUtxoError> {
        metadata
            .validate()
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        if self
            .journals
            .get(&block_hash)
            .is_some_and(|journal| journal.block_height != height)
        {
            return Err(QCashUtxoError::InvalidMetadata);
        }
        let previous_journal_tip = self.active_journal_tip;
        let ids = self.apply_withdraw(withdrawer, withdraw_tx_hash, metadata, height)?;
        let journal = self
            .journals
            .entry(block_hash)
            .or_insert_with(|| QCashBlockJournal {
                block_hash,
                block_height: height,
                previous_journal_tip,
                issued_coin_ids: Vec::new(),
                redeemed_utxos: Vec::new(),
            });
        journal.issued_coin_ids.extend(ids.iter().copied());
        self.active_journal_tip = Some(block_hash);
        Ok(ids)
    }

    pub fn apply_redeem_in_block(
        &mut self,
        block_hash: BlockHash,
        height: BlockHeight,
        metadata: &QCashRedeemMetadata,
        recipient: Address,
        transaction_commitment: [u8; 32],
    ) -> Result<Amount, QCashUtxoError> {
        metadata
            .validate_authorizations_for_transaction(recipient, transaction_commitment)
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let (ids, amount) = self.validate_redeem(metadata, height)?;
        let previous = ids
            .iter()
            .map(|id| {
                self.coins
                    .get(id)
                    .cloned()
                    .ok_or(QCashUtxoError::UnknownCoin)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let previous_journal_tip = self.active_journal_tip;
        let journal = self
            .journals
            .entry(block_hash)
            .or_insert_with(|| QCashBlockJournal {
                block_hash,
                block_height: height,
                previous_journal_tip,
                issued_coin_ids: Vec::new(),
                redeemed_utxos: Vec::new(),
            });
        if journal.block_height != height {
            return Err(QCashUtxoError::InvalidMetadata);
        }
        for id in &ids {
            self.coins.remove(id).ok_or(QCashUtxoError::UnknownCoin)?;
        }
        let journal = self
            .journals
            .get_mut(&block_hash)
            .ok_or(QCashUtxoError::MissingBlockJournal)?;
        journal.redeemed_utxos.extend(previous);
        self.active_journal_tip = Some(block_hash);
        Ok(amount)
    }

    /// Reverses all QCash changes made by a disconnected block.
    pub fn rollback_block(&mut self, block_hash: BlockHash) -> Result<(), QCashUtxoError> {
        if self.active_journal_tip != Some(block_hash) {
            return Err(QCashUtxoError::NonTipRollback);
        }
        let journal = self
            .journals
            .remove(&block_hash)
            .ok_or(QCashUtxoError::MissingBlockJournal)?;
        for previous in journal.redeemed_utxos.into_iter().rev() {
            self.coins.insert(previous.id, previous);
        }
        for id in journal.issued_coin_ids {
            self.coins.remove(&id);
        }
        self.active_journal_tip = journal.previous_journal_tip;
        Ok(())
    }

    pub fn set_active_journal_tip(
        &mut self,
        block_hash: Option<BlockHash>,
    ) -> Result<(), QCashUtxoError> {
        if let Some(hash) = block_hash
            && !self.journals.contains_key(&hash)
        {
            return Err(QCashUtxoError::MissingBlockJournal);
        }
        self.active_journal_tip = block_hash;
        Ok(())
    }

    pub fn prune_journals(&mut self, finalized_height: BlockHeight) {
        self.journals
            .retain(|_, journal| journal.block_height > finalized_height);
        let retained = self.journals.keys().copied().collect::<BTreeSet<_>>();
        for journal in self.journals.values_mut() {
            if journal
                .previous_journal_tip
                .is_some_and(|hash| !retained.contains(&hash))
            {
                journal.previous_journal_tip = None;
            }
        }
        if self
            .active_journal_tip
            .is_some_and(|tip| !self.journals.contains_key(&tip))
        {
            self.active_journal_tip = None;
        }
    }

    fn validate_redeem(
        &self,
        metadata: &QCashRedeemMetadata,
        height: BlockHeight,
    ) -> Result<(Vec<QCashCoinId>, Amount), QCashUtxoError> {
        let mut ids = Vec::with_capacity(metadata.inputs.len());
        for input in &metadata.inputs {
            let id = QCashCoinId(input.coin_id);
            let coin = self.coins.get(&id).ok_or(QCashUtxoError::UnknownCoin)?;
            if !is_redeemable_at(coin, height) {
                return Err(QCashUtxoError::CoinNotRedeemable);
            }
            if coin.denomination != input.denomination
                || coin.redeem_key_commitment
                    != qcash_redeem_key_commitment(&input.redeem_public_key)
            {
                return Err(QCashUtxoError::InvalidCoinProof);
            }
            ids.push(id);
        }
        let amount = metadata
            .amount()
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        Ok((ids, amount))
    }
}

fn is_redeemable_at(coin: &QCashUtxo, height: BlockHeight) -> bool {
    coin.issued_height
        .0
        .checked_add(crate::ledger::QCASH_REDEEM_DELAY as u64)
        .is_some_and(|maturity_height| height.0 >= maturity_height)
}

#[cfg(test)]
mod tests {
    use super::super::proof::verify_qcash_state_proof;
    use super::*;
    use crate::crypto::{HashDomain, domain_hash};

    fn coin(byte: u8) -> QCashUtxo {
        QCashUtxo {
            id: QCashCoinId([byte; HASH_SIZE]),
            outpoint: QCashOutPoint {
                transaction_hash: TransactionHash([byte.wrapping_add(1); HASH_SIZE]),
                output_index: u32::from(byte),
            },
            withdrawer: Address([byte.wrapping_add(2); crate::crypto::ADDRESS_SIZE]),
            denomination: QCashDenomination::Ten,
            redeem_key_commitment: [byte.wrapping_add(3); HASH_SIZE],
            issued_height: Height(u64::from(byte)),
        }
    }

    #[test]
    fn withdrawn_coin_is_redeemable_starting_in_the_next_block() {
        let coin = coin(100);

        assert_eq!(
            coin.redeemability_at(Height(100)),
            QCashRedeemability::Pending
        );
        assert_eq!(
            coin.redeemability_at(Height(101)),
            QCashRedeemability::Redeemable
        );
    }

    #[test]
    fn qcash_default_file_name_uses_full_coin_id() {
        let coin_id = QCashCoinId([0xAB; HASH_SIZE]);
        let full_id = "AB".repeat(HASH_SIZE);

        assert_eq!(
            coin_id.file_name(QCashDenomination::One),
            format!("1XPQ_{full_id}.QCash")
        );
        assert_eq!(
            coin_id.file_name(QCashDenomination::OneMillion),
            format!("1000000XPQ_{full_id}.QCash")
        );
    }

    #[test]
    fn empty_authenticated_root_preserves_frozen_v1_commitment() {
        let set = QCashUtxoSet::default();
        let legacy = domain_hash(
            HashDomain::QCashState,
            &crate::codec::canonical_bytes(&set.coins).unwrap(),
        );

        assert_eq!(set.consensus_root().unwrap(), legacy);
    }

    #[test]
    fn qcash_membership_and_non_membership_proofs_verify() {
        let mut set = QCashUtxoSet::default();
        let first = coin(0x11);
        let second = coin(0x88);
        set.coins.insert(first.id, first.clone());
        set.coins.insert(second.id, second);
        let root = set.consensus_root().unwrap();

        let membership = set.create_state_proof(first.id).unwrap();
        assert_eq!(membership.coin, Some(first));
        assert!(verify_qcash_state_proof(root, &membership).unwrap());

        let absence = set
            .create_state_proof(QCashCoinId([0x44; HASH_SIZE]))
            .unwrap();
        assert!(absence.coin.is_none());
        assert!(verify_qcash_state_proof(root, &absence).unwrap());
    }

    #[test]
    fn qcash_proof_rejects_coin_and_path_tampering() {
        let mut set = QCashUtxoSet::default();
        let existing = coin(0x22);
        set.coins.insert(existing.id, existing.clone());
        let root = set.consensus_root().unwrap();

        let mut membership = set.create_state_proof(existing.id).unwrap();
        membership.coin.as_mut().unwrap().redeem_key_commitment[0] ^= 1;
        assert!(!verify_qcash_state_proof(root, &membership).unwrap());

        let mut absence = set
            .create_state_proof(QCashCoinId([0x99; HASH_SIZE]))
            .unwrap();
        absence.siblings[0].hash.0[0] ^= 1;
        assert!(!verify_qcash_state_proof(root, &absence).unwrap());
    }

    #[test]
    fn consecutive_journal_rollbacks_restore_parent_tip() {
        let parent = BlockHash([0x11; crate::crypto::HASH_SIZE]);
        let child = BlockHash([0x22; crate::crypto::HASH_SIZE]);
        let mut set = QCashUtxoSet::default();
        set.journals.insert(
            parent,
            QCashBlockJournal {
                block_hash: parent,
                block_height: crate::block::Height(1),
                previous_journal_tip: None,
                issued_coin_ids: Vec::new(),
                redeemed_utxos: Vec::new(),
            },
        );
        set.journals.insert(
            child,
            QCashBlockJournal {
                block_hash: child,
                block_height: crate::block::Height(2),
                previous_journal_tip: Some(parent),
                issued_coin_ids: Vec::new(),
                redeemed_utxos: Vec::new(),
            },
        );
        set.active_journal_tip = Some(child);

        set.rollback_block(child).unwrap();
        assert_eq!(set.active_journal_tip, Some(parent));
        set.rollback_block(parent).unwrap();
        assert_eq!(set.active_journal_tip, None);
    }

    #[test]
    fn finalized_journal_pruning_rebases_retained_rollback_chain() {
        let finalized = BlockHash([0x31; crate::crypto::HASH_SIZE]);
        let retained = BlockHash([0x32; crate::crypto::HASH_SIZE]);
        let tip = BlockHash([0x33; crate::crypto::HASH_SIZE]);
        let mut set = QCashUtxoSet::default();
        for (block_hash, block_height, previous_journal_tip) in [
            (finalized, Height(5), None),
            (retained, Height(6), Some(finalized)),
            (tip, Height(7), Some(retained)),
        ] {
            set.journals.insert(
                block_hash,
                QCashBlockJournal {
                    block_hash,
                    block_height,
                    previous_journal_tip,
                    issued_coin_ids: Vec::new(),
                    redeemed_utxos: Vec::new(),
                },
            );
        }
        set.active_journal_tip = Some(tip);

        set.prune_journals(Height(5));

        assert!(!set.journals.contains_key(&finalized));
        assert_eq!(
            set.journals.get(&retained).unwrap().previous_journal_tip,
            None
        );
        assert_eq!(
            set.journals.get(&tip).unwrap().previous_journal_tip,
            Some(retained)
        );
        set.rollback_block(tip).unwrap();
        set.rollback_block(retained).unwrap();
        assert_eq!(set.active_journal_tip, None);
    }

    #[test]
    fn failed_block_withdraw_leaves_coins_and_journal_state_unchanged() {
        let parent = BlockHash([0x41; crate::crypto::HASH_SIZE]);
        let block_hash = BlockHash([0x42; crate::crypto::HASH_SIZE]);
        let withdraw_tx_hash = TransactionHash([0x43; crate::crypto::HASH_SIZE]);
        let metadata = QCashWithdrawalMetadata::with_denominations(
            QCashDenomination::Ten.amount(),
            &[QCashDenomination::Ten],
            &[[0x44; 32]],
        )
        .unwrap();
        let collision_id = QCashCoinId::derive(withdraw_tx_hash, &metadata.outputs[0]).unwrap();
        let mut existing = coin(0x45);
        existing.id = collision_id;

        let mut set = QCashUtxoSet::default();
        set.coins.insert(collision_id, existing);
        set.journals.insert(
            parent,
            QCashBlockJournal {
                block_hash: parent,
                block_height: Height(10),
                previous_journal_tip: None,
                issued_coin_ids: Vec::new(),
                redeemed_utxos: Vec::new(),
            },
        );
        set.active_journal_tip = Some(parent);
        let before = set.clone();

        assert_eq!(
            set.apply_withdraw_in_block(
                block_hash,
                Height(11),
                Address([0x46; crate::crypto::ADDRESS_SIZE]),
                withdraw_tx_hash,
                &metadata,
            ),
            Err(QCashUtxoError::CoinIdCollision)
        );
        assert_eq!(set, before);
    }
}
