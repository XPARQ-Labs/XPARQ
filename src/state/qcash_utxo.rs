//! Consensus UTXO set for QCash bearer outputs.

use crate::block::{BlockHeight, Height};
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, BlockHash, HASH_SIZE, Hash, HashDomain, TransactionHash, domain_hash,
};
use crate::qcash::{
    QCashDenomination, QCashDepositMetadata, QCashError, QCashOutput, QCashWithdrawMetadata,
    qcash_coin_id_bytes, qcash_spend_public_key_commitment,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

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
        output: &QCashOutput,
    ) -> Result<Self, QCashError> {
        Ok(Self(qcash_coin_id_bytes(withdraw_tx_hash, output)?))
    }

    /// Sixteen uppercase hexadecimal characters for a human-facing file name.
    pub fn short_id(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut value = String::with_capacity(16);
        for byte in self.0.iter().take(8) {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        value
    }

    pub fn file_name(&self, denomination: QCashDenomination) -> String {
        format!("{}_{}.XPQ", denomination.xpq(), self.short_id())
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
pub enum QCashUtxoStatus {
    Immature,
    Mature,
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
    pub commitment: [u8; 32],
    pub issued_height: BlockHeight,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum QCashProofSide {
    Left,
    Right,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct QCashStateProofNode {
    pub side: QCashProofSide,
    pub hash: Hash,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct QCashStateProof {
    pub coin_id: QCashCoinId,
    pub coin: Option<QCashUtxo>,
    /// For absence, the depth of the first committed empty subtree. Membership
    /// proofs always terminate at depth 256.
    pub terminal_depth: u16,
    pub siblings: Vec<QCashStateProofNode>,
}

impl QCashUtxo {
    pub fn status_at(&self, height: BlockHeight) -> QCashUtxoStatus {
        if is_mature_at(self, height) {
            QCashUtxoStatus::Mature
        } else {
            QCashUtxoStatus::Immature
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct QCashBlockJournal {
    pub block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub previous_journal_tip: Option<BlockHash>,
    pub issued_coin_ids: Vec<QCashCoinId>,
    pub spent_utxos: Vec<QCashUtxo>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Default,
)]
pub struct QCashUtxoSet {
    coins: BTreeMap<QCashCoinId, QCashUtxo>,
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
    CoinImmature,
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
            Self::UnknownCoin => f.write_str("QCash output is unknown or already spent"),
            Self::DuplicateCoin => f.write_str("QCash coin is repeated in the operation"),
            Self::DenominationMismatch => {
                f.write_str("QCash coin denominations do not match metadata")
            }
            Self::CoinIdCollision => f.write_str("derived QCash coin ID already exists"),
            Self::InvalidCoinProof => f.write_str("QCash coin proof does not match issued output"),
            Self::CoinDerivation(error) => write!(f, "failed to derive QCash coin ID: {error}"),
            Self::CoinImmature => {
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

    pub fn mature_utxos_at(&self, height: BlockHeight) -> impl Iterator<Item = &QCashUtxo> {
        self.coins
            .values()
            .filter(move |coin| is_mature_at(coin, height))
    }

    pub fn mature_utxos(&self) -> impl Iterator<Item = &QCashUtxo> {
        self.mature_utxos_at(Height(u64::MAX))
    }

    pub fn utxos(&self) -> impl Iterator<Item = &QCashUtxo> {
        self.coins.values()
    }

    pub fn mature_balance(&self) -> Result<Amount, QCashUtxoError> {
        self.mature_utxos().try_fold(Amount(0), |total, coin| {
            total
                .0
                .checked_add(coin.denomination.amount().0)
                .map(Amount)
                .ok_or(QCashUtxoError::StateOverflow)
        })
    }

    pub fn mature_balance_at(&self, height: BlockHeight) -> Result<Amount, QCashUtxoError> {
        self.mature_utxos_at(height)
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
        metadata: &QCashWithdrawMetadata,
        height: BlockHeight,
    ) -> Result<Vec<QCashCoinId>, QCashUtxoError> {
        metadata
            .validate()
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let mut pending: Vec<(QCashCoinId, &QCashOutput)> =
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
                    commitment: output.commitment,
                    issued_height: height,
                },
            );
            ids.push(id);
        }
        Ok(ids)
    }

    /// Verifies bearer secrets and atomically redeems explicit deposit inputs.
    pub fn apply_deposit_proof(
        &mut self,
        metadata: &QCashDepositMetadata,
        recipient: Address,
        height: BlockHeight,
        transaction_commitment: [u8; 32],
    ) -> Result<Amount, QCashUtxoError> {
        metadata
            .validate_authorizations_for_transaction(recipient, transaction_commitment)
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let (ids, amount) = self.validate_deposit_proof(metadata, height)?;
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
        metadata: &QCashWithdrawMetadata,
    ) -> Result<Vec<QCashCoinId>, QCashUtxoError> {
        metadata
            .validate()
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let previous_journal_tip = self.active_journal_tip;
        let journal = self
            .journals
            .entry(block_hash)
            .or_insert_with(|| QCashBlockJournal {
                block_hash,
                block_height: height,
                previous_journal_tip,
                issued_coin_ids: Vec::new(),
                spent_utxos: Vec::new(),
            });
        if journal.block_height != height {
            return Err(QCashUtxoError::InvalidMetadata);
        }
        let ids = self.apply_withdraw(withdrawer, withdraw_tx_hash, metadata, height)?;
        let journal = self
            .journals
            .get_mut(&block_hash)
            .ok_or(QCashUtxoError::MissingBlockJournal)?;
        journal.issued_coin_ids.extend(ids.iter().copied());
        self.active_journal_tip = Some(block_hash);
        Ok(ids)
    }

    pub fn apply_deposit_in_block(
        &mut self,
        block_hash: BlockHash,
        height: BlockHeight,
        metadata: &QCashDepositMetadata,
        recipient: Address,
        transaction_commitment: [u8; 32],
    ) -> Result<Amount, QCashUtxoError> {
        metadata
            .validate_authorizations_for_transaction(recipient, transaction_commitment)
            .map_err(|_| QCashUtxoError::InvalidMetadata)?;
        let (ids, amount) = self.validate_deposit_proof(metadata, height)?;
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
                spent_utxos: Vec::new(),
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
        journal.spent_utxos.extend(previous);
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
        for previous in journal.spent_utxos.into_iter().rev() {
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
        if self
            .active_journal_tip
            .is_some_and(|tip| !self.journals.contains_key(&tip))
        {
            self.active_journal_tip = None;
        }
    }

    fn validate_deposit_proof(
        &self,
        metadata: &QCashDepositMetadata,
        height: BlockHeight,
    ) -> Result<(Vec<QCashCoinId>, Amount), QCashUtxoError> {
        let mut ids = Vec::with_capacity(metadata.inputs.len());
        for input in &metadata.inputs {
            let id = QCashCoinId(input.coin_id);
            let coin = self.coins.get(&id).ok_or(QCashUtxoError::UnknownCoin)?;
            if !is_mature_at(coin, height) {
                return Err(QCashUtxoError::CoinImmature);
            }
            if coin.denomination != input.denomination
                || coin.commitment != qcash_spend_public_key_commitment(&input.spend_public_key)
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

const QCASH_KEY_BITS: usize = HASH_SIZE * 8;

struct QCashSparseStateTree {
    nodes: BTreeMap<(usize, [u8; HASH_SIZE]), Hash>,
    root: Hash,
}

impl QCashSparseStateTree {
    fn from_coins(
        coins: &BTreeMap<QCashCoinId, QCashUtxo>,
    ) -> Result<Self, crate::error::CodecError> {
        if coins.is_empty() {
            return Ok(Self {
                nodes: BTreeMap::new(),
                // Preserve the frozen genesis commitment while changing
                // non-empty QCash state to the authenticated tree.
                root: empty_qcash_state_root()?,
            });
        }
        let mut tree = Self {
            nodes: BTreeMap::new(),
            root: empty_qcash_state_root()?,
        };
        for coin in coins.values() {
            tree.nodes
                .insert((QCASH_KEY_BITS, coin.id.0), qcash_leaf_hash(coin)?);
            tree.recalculate_path(coin.id);
        }
        Ok(tree)
    }

    fn root(&self) -> Hash {
        self.root
    }

    fn recalculate_path(&mut self, coin_id: QCashCoinId) {
        for depth in (0..QCASH_KEY_BITS).rev() {
            let parent_prefix = qcash_prefix(&coin_id, depth);
            let left_prefix = qcash_child_prefix(parent_prefix, depth, false);
            let right_prefix = qcash_child_prefix(parent_prefix, depth, true);
            let left = self.nodes.get(&(depth + 1, left_prefix)).copied();
            let right = self.nodes.get(&(depth + 1, right_prefix)).copied();
            if left.is_none() && right.is_none() {
                self.nodes.remove(&(depth, parent_prefix));
            } else {
                self.nodes.insert(
                    (depth, parent_prefix),
                    qcash_parent_hash(
                        left.unwrap_or_else(|| qcash_empty_hash(depth + 1)),
                        right.unwrap_or_else(|| qcash_empty_hash(depth + 1)),
                    ),
                );
            }
        }
        self.root = self.nodes[&(0, [0; HASH_SIZE])];
    }

    fn create_proof(
        &self,
        coin_id: QCashCoinId,
        coin: Option<QCashUtxo>,
    ) -> Result<QCashStateProof, crate::error::CodecError> {
        if self.nodes.is_empty() {
            return Ok(QCashStateProof {
                coin_id,
                coin: None,
                terminal_depth: 0,
                siblings: Vec::new(),
            });
        }
        let mut siblings = Vec::with_capacity(QCASH_KEY_BITS);
        for depth in 0..QCASH_KEY_BITS {
            let parent_prefix = qcash_prefix(&coin_id, depth);
            let bit = qcash_bit(&coin_id, depth);
            let sibling_prefix = qcash_child_prefix(parent_prefix, depth, !bit);
            siblings.push(QCashStateProofNode {
                side: if bit {
                    QCashProofSide::Left
                } else {
                    QCashProofSide::Right
                },
                hash: self
                    .nodes
                    .get(&(depth + 1, sibling_prefix))
                    .copied()
                    .unwrap_or_else(|| qcash_empty_hash(depth + 1)),
            });
            let target_prefix = qcash_child_prefix(parent_prefix, depth, bit);
            if !self.nodes.contains_key(&(depth + 1, target_prefix)) {
                return Ok(QCashStateProof {
                    coin_id,
                    coin: None,
                    terminal_depth: (depth + 1) as u16,
                    siblings,
                });
            }
        }
        Ok(QCashStateProof {
            coin_id,
            coin,
            terminal_depth: QCASH_KEY_BITS as u16,
            siblings,
        })
    }
}

pub fn verify_qcash_state_proof(
    root: Hash,
    proof: &QCashStateProof,
) -> Result<bool, crate::error::CodecError> {
    let terminal_depth = usize::from(proof.terminal_depth);
    if terminal_depth > QCASH_KEY_BITS || proof.siblings.len() != terminal_depth {
        return Ok(false);
    }
    if proof.siblings.iter().enumerate().any(|(depth, sibling)| {
        let expected = if qcash_bit(&proof.coin_id, depth) {
            QCashProofSide::Left
        } else {
            QCashProofSide::Right
        };
        sibling.side != expected
    }) {
        return Ok(false);
    }
    let mut current = match &proof.coin {
        Some(coin) => {
            if terminal_depth != QCASH_KEY_BITS || coin.id != proof.coin_id {
                return Ok(false);
            }
            qcash_leaf_hash(coin)?
        }
        None => {
            if terminal_depth == 0 {
                return Ok(root == empty_qcash_state_root()?);
            }
            qcash_empty_hash(terminal_depth)
        }
    };
    for sibling in proof.siblings.iter().rev() {
        current = match sibling.side {
            QCashProofSide::Left => qcash_parent_hash(sibling.hash, current),
            QCashProofSide::Right => qcash_parent_hash(current, sibling.hash),
        };
    }
    Ok(current == root)
}

pub fn empty_qcash_state_root() -> Result<Hash, crate::error::CodecError> {
    let empty: BTreeMap<QCashCoinId, QCashUtxo> = BTreeMap::new();
    Ok(domain_hash(
        HashDomain::QCashState,
        &crate::codec::canonical_bytes(&empty)?,
    ))
}

fn qcash_leaf_hash(coin: &QCashUtxo) -> Result<Hash, crate::error::CodecError> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&crate::codec::canonical_bytes(coin)?);
    Ok(domain_hash(HashDomain::QCashState, &bytes))
}

fn qcash_empty_hash(depth: usize) -> Hash {
    let mut bytes = Vec::with_capacity(9);
    bytes.push(1);
    bytes.extend_from_slice(&(depth as u64).to_le_bytes());
    domain_hash(HashDomain::QCashState, &bytes)
}

fn qcash_parent_hash(left: Hash, right: Hash) -> Hash {
    let mut bytes = Vec::with_capacity(1 + HASH_SIZE * 2);
    bytes.push(2);
    bytes.extend_from_slice(&left.0);
    bytes.extend_from_slice(&right.0);
    domain_hash(HashDomain::QCashState, &bytes)
}

fn qcash_bit(coin_id: &QCashCoinId, depth: usize) -> bool {
    coin_id.0[depth / 8] & (0x80_u8 >> (depth % 8)) != 0
}

fn qcash_prefix(coin_id: &QCashCoinId, depth: usize) -> [u8; HASH_SIZE] {
    let mut prefix = coin_id.0;
    qcash_clear_bits_from(&mut prefix, depth);
    prefix
}

fn qcash_child_prefix(
    mut parent_prefix: [u8; HASH_SIZE],
    depth: usize,
    right: bool,
) -> [u8; HASH_SIZE] {
    qcash_clear_bits_from(&mut parent_prefix, depth);
    if right {
        parent_prefix[depth / 8] |= 0x80_u8 >> (depth % 8);
    }
    qcash_clear_bits_from(&mut parent_prefix, depth + 1);
    parent_prefix
}

fn qcash_clear_bits_from(bytes: &mut [u8; HASH_SIZE], depth: usize) {
    if depth >= QCASH_KEY_BITS {
        return;
    }
    let byte_index = depth / 8;
    let bit_index = depth % 8;
    if bit_index == 0 {
        bytes[byte_index] = 0;
    } else {
        bytes[byte_index] &= 0xff_u8 << (8 - bit_index);
    }
    for byte in &mut bytes[(byte_index + 1)..] {
        *byte = 0;
    }
}

fn is_mature_at(coin: &QCashUtxo, height: BlockHeight) -> bool {
    coin.issued_height
        .0
        .checked_add(crate::ledger::QCASH_DEPOSIT_DELAY as u64)
        .is_some_and(|maturity_height| height.0 >= maturity_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(byte: u8) -> QCashUtxo {
        QCashUtxo {
            id: QCashCoinId([byte; HASH_SIZE]),
            outpoint: QCashOutPoint {
                transaction_hash: TransactionHash([byte.wrapping_add(1); HASH_SIZE]),
                output_index: u32::from(byte),
            },
            withdrawer: Address([byte.wrapping_add(2); crate::crypto::ADDRESS_SIZE]),
            denomination: QCashDenomination::Ten,
            commitment: [byte.wrapping_add(3); HASH_SIZE],
            issued_height: Height(u64::from(byte)),
        }
    }

    #[test]
    fn withdrawn_coin_is_depositable_starting_in_the_next_block() {
        let coin = coin(100);

        assert_eq!(coin.status_at(Height(100)), QCashUtxoStatus::Immature);
        assert_eq!(coin.status_at(Height(101)), QCashUtxoStatus::Mature);
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
        membership.coin.as_mut().unwrap().commitment[0] ^= 1;
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
                spent_utxos: Vec::new(),
            },
        );
        set.journals.insert(
            child,
            QCashBlockJournal {
                block_hash: child,
                block_height: crate::block::Height(2),
                previous_journal_tip: Some(parent),
                issued_coin_ids: Vec::new(),
                spent_utxos: Vec::new(),
            },
        );
        set.active_journal_tip = Some(child);

        set.rollback_block(child).unwrap();
        assert_eq!(set.active_journal_tip, Some(parent));
        set.rollback_block(parent).unwrap();
        assert_eq!(set.active_journal_tip, None);
    }
}
