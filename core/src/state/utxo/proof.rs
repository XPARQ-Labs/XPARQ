//! Authenticated sparse-state proofs for QCash bearer outputs.

use super::qcash::{QCashCoinId, QCashUtxo};
use crate::crypto::{HASH_SIZE, Hash, HashDomain, domain_hash};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;

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

const QCASH_KEY_BITS: usize = HASH_SIZE * 8;

pub(super) struct QCashSparseStateTree {
    nodes: BTreeMap<(usize, [u8; HASH_SIZE]), Hash>,
    root: Hash,
}

impl QCashSparseStateTree {
    pub(super) fn from_coins(
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

    pub(super) fn root(&self) -> Hash {
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

    pub(super) fn create_proof(
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
    // Empty subtrees inside a non-empty sparse tree use depth-separated
    // hashes. The whole-tree-empty case deliberately uses the frozen legacy
    // commitment returned by `empty_qcash_state_root`.
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
