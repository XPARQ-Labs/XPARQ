use crate::block::Block;
use crate::block::{BlockHeight, Height};
use crate::consensus::{
    Consensus, DIFFICULTY_START, MIN_DIFFICULTY, WBDA_WINDOW, is_wbda_epoch_boundary,
    next_difficulty_from_window,
};
use crate::crypto::{BlockHash, HASH_SIZE, Hash};
use borsh::{BorshDeserialize, BorshSerialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::ops::Add;

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct Work([u64; 8]);

impl Work {
    pub const ZERO: Self = Self([0; 8]);
    pub const MAX: Self = Self([u64::MAX; 8]);

    pub fn to_be_limbs(self) -> [u64; 8] {
        self.0
    }

    pub const fn from_be_limbs(limbs: [u64; 8]) -> Self {
        Self(limbs)
    }

    pub fn pow2(exponent: u32) -> Self {
        if exponent >= 512 {
            return Self::MAX;
        }

        let limb_from_low = (exponent / 64) as usize;
        let bit = exponent % 64;
        let mut limbs = [0; 8];
        limbs[7 - limb_from_low] = 1_u64 << bit;
        Self(limbs)
    }

    pub fn saturating_add(self, rhs: Self) -> Self {
        let mut result = [0; 8];
        let mut carry = 0_u128;

        for index in (0..result.len()).rev() {
            let sum = self.0[index] as u128 + rhs.0[index] as u128 + carry;
            result[index] = sum as u64;
            carry = sum >> 64;
        }

        if carry > 0 { Self::MAX } else { Self(result) }
    }
}

impl Add for Work {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockNode {
    pub block: Block,
    pub hash: BlockHash,
    pub parent: BlockHash,
    pub height: BlockHeight,
    pub work: Work,
    pub cumulative_work: Work,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkChoice {
    expected_genesis: BlockHash,
    nodes: BTreeMap<BlockHash, BlockNode>,
    best_tip: Option<BlockHash>,
}

impl ForkChoice {
    pub fn new(expected_genesis: BlockHash) -> Self {
        Self {
            expected_genesis,
            nodes: BTreeMap::new(),
            best_tip: None,
        }
    }

    pub fn insert_block(&mut self, block: Block) -> Result<BlockHash, ForkChoiceError> {
        let hash = block.hash().map_err(ForkChoiceError::Serialization)?;
        if self.nodes.contains_key(&hash) {
            return Err(ForkChoiceError::DuplicateBlock);
        }

        if block.difficulty() < MIN_DIFFICULTY {
            return Err(ForkChoiceError::InvalidDifficulty);
        }

        let parent = BlockHash(block.previous_hash().0);
        let parent_work = if block.height() == Height(0) {
            if hash != self.expected_genesis {
                return Err(ForkChoiceError::UnexpectedGenesis);
            }
            if parent != Hash([0; HASH_SIZE]) {
                return Err(ForkChoiceError::MissingParent);
            }
            Work::ZERO
        } else {
            let parent_node = self
                .nodes
                .get(&parent)
                .ok_or(ForkChoiceError::MissingParent)?;
            if block.height().0 != parent_node.height.0.saturating_add(1) {
                return Err(ForkChoiceError::InvalidHeight);
            }
            parent_node.cumulative_work
        };
        let expected_difficulty = self.expected_difficulty_for(&block, parent)?;
        if !block.is_genesis() {
            if block.difficulty() != expected_difficulty {
                return Err(ForkChoiceError::InvalidDifficulty);
            }
            Consensus::validate_pow_at_difficulty(&block, expected_difficulty)
                .map_err(ForkChoiceError::InvalidProofOfWork)?;
        }

        let work = if block.is_genesis() {
            Work::ZERO
        } else {
            block_work(expected_difficulty)
        };
        let cumulative_work = parent_work.saturating_add(work);
        let node = BlockNode {
            height: block.height(),
            parent,
            hash,
            work,
            cumulative_work,
            block,
        };

        self.nodes.insert(hash, node);
        self.update_best_tip(hash);
        Ok(hash)
    }

    /// Indexes an authenticated header when its historical block body is
    /// intentionally absent (for example below a snapshot checkpoint).
    ///
    /// Header consensus rules and PoW are checked exactly as for a full block.
    pub fn insert_header(
        &mut self,
        header: crate::qcash::recovery::ChainHeader,
    ) -> Result<BlockHash, ForkChoiceError> {
        self.insert_block(header.block())
    }

    pub fn best_tip(&self) -> Option<&BlockNode> {
        self.best_tip.and_then(|hash| self.nodes.get(&hash))
    }

    pub fn get(&self, hash: &BlockHash) -> Option<&BlockNode> {
        self.nodes.get(hash)
    }

    pub fn ancestor_hashes(&self, hash: BlockHash) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        let mut current = hash;

        while let Some(node) = self.nodes.get(&current) {
            hashes.push(current);
            if node.height.0 == 0 {
                break;
            }
            current = node.parent;
        }

        hashes
    }

    pub fn ancestor_hash_at_height(
        &self,
        hash: BlockHash,
        height: BlockHeight,
    ) -> Option<BlockHash> {
        self.ancestor_at_height(hash, height).map(|node| node.hash)
    }

    pub fn branch_from_ancestor(&self, ancestor: BlockHash, tip: BlockHash) -> Option<Vec<Block>> {
        let mut blocks = Vec::new();
        let mut current = tip;

        while current != ancestor {
            let node = self.nodes.get(&current)?;
            blocks.push(node.block.clone());
            current = node.parent;
        }

        blocks.reverse();
        Some(blocks)
    }

    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.nodes.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Removes branches that diverged before `finalized`, while retaining the
    /// complete ancestry of the finalized block and every descendant of it.
    ///
    /// Keeping the finalized ancestry allows callers to replay the active
    /// chain from genesis. A finalized block must be on the current best chain;
    /// accepting any other anchor could discard the selected chain.
    pub fn prune_finalized(&mut self, finalized: BlockHash) -> Result<usize, ForkChoiceError> {
        if !self.nodes.contains_key(&finalized) {
            return Err(ForkChoiceError::UnknownFinalizedBlock);
        }

        let best_tip = self
            .best_tip
            .ok_or(ForkChoiceError::UnknownFinalizedBlock)?;
        if !self.ancestor_hashes(best_tip).contains(&finalized) {
            return Err(ForkChoiceError::FinalizedBlockNotOnBestChain);
        }

        let finalized_ancestors: std::collections::BTreeSet<_> =
            self.ancestor_hashes(finalized).into_iter().collect();
        let old_len = self.nodes.len();
        let retained: std::collections::BTreeSet<_> = self
            .nodes
            .keys()
            .copied()
            .filter(|hash| {
                finalized_ancestors.contains(hash)
                    || Self::descends_from_in(&self.nodes, *hash, finalized)
            })
            .collect();
        self.nodes.retain(|hash, _| retained.contains(hash));
        Ok(old_len.saturating_sub(self.nodes.len()))
    }

    fn descends_from_in(
        nodes: &BTreeMap<BlockHash, BlockNode>,
        hash: BlockHash,
        ancestor: BlockHash,
    ) -> bool {
        let mut current = hash;
        while let Some(node) = nodes.get(&current) {
            if current == ancestor {
                return true;
            }
            if node.height.0 == 0 {
                return false;
            }
            current = node.parent;
        }
        false
    }

    fn update_best_tip(&mut self, candidate_hash: BlockHash) {
        let Some(candidate) = self.nodes.get(&candidate_hash) else {
            return;
        };

        let should_update = match self.best_tip.and_then(|hash| self.nodes.get(&hash)) {
            None => true,
            Some(best) => compare_chain_tips(
                candidate.cumulative_work,
                candidate.hash,
                best.cumulative_work,
                best.hash,
            )
            .is_gt(),
        };

        if should_update {
            self.best_tip = Some(candidate_hash);
        }
    }

    fn expected_difficulty_for(
        &self,
        block: &Block,
        parent: BlockHash,
    ) -> Result<u32, ForkChoiceError> {
        if block.height() == Height(0) {
            return Ok(DIFFICULTY_START);
        }
        let parent_node = self
            .nodes
            .get(&parent)
            .ok_or(ForkChoiceError::MissingParent)?;
        if !is_wbda_epoch_boundary(block.height().0) {
            return Ok(parent_node.block.difficulty());
        }

        let mut weights = Vec::with_capacity(WBDA_WINDOW);
        let mut current = parent;
        for _ in 0..WBDA_WINDOW {
            let node = self
                .nodes
                .get(&current)
                .ok_or(ForkChoiceError::MissingParent)?;
            weights.push(
                node.block
                    .block_weight()
                    .try_into()
                    .map_err(|_| ForkChoiceError::InvalidDifficulty)?,
            );
            if node.height == Height(0) {
                break;
            }
            current = node.parent;
        }
        if weights.len() != WBDA_WINDOW {
            return Err(ForkChoiceError::MissingParent);
        }
        weights.reverse();
        next_difficulty_from_window(parent_node.block.difficulty(), &weights)
            .ok_or(ForkChoiceError::MissingParent)
    }

    fn ancestor_at_height(&self, hash: BlockHash, height: Height) -> Option<&BlockNode> {
        let mut current = hash;
        loop {
            let node = self.nodes.get(&current)?;
            if node.height == height {
                return Some(node);
            }
            if node.height < height || node.height.0 == 0 {
                return None;
            }
            current = node.parent;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkChoiceError {
    DuplicateBlock,
    UnexpectedGenesis,
    InvalidDifficulty,
    InvalidProofOfWork(crate::error::ConsensusError),
    InvalidHeight,
    MissingParent,
    UnknownFinalizedBlock,
    FinalizedBlockNotOnBestChain,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBlock => f.write_str("block already exists in fork graph"),
            Self::UnexpectedGenesis => {
                f.write_str("fork graph genesis does not match the configured chain")
            }
            Self::InvalidDifficulty => f.write_str("block difficulty is invalid for its branch"),
            Self::InvalidProofOfWork(error) => write!(f, "block proof of work is invalid: {error}"),
            Self::InvalidHeight => f.write_str("block height does not follow its parent"),
            Self::MissingParent => f.write_str("block parent is missing from fork graph"),
            Self::UnknownFinalizedBlock => {
                f.write_str("finalized block is missing from fork graph")
            }
            Self::FinalizedBlockNotOnBestChain => {
                f.write_str("finalized block is not on the selected best chain")
            }
            Self::Serialization(error) => write!(f, "fork graph encoding failed: {error}"),
        }
    }
}

impl Error for ForkChoiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidProofOfWork(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

pub fn block_work(difficulty: u32) -> Work {
    Work::pow2(difficulty)
}

/// Consensus ordering for valid chain tips.
///
/// Greater locally-computed cumulative work wins. Equal-work branches use the
/// numerically smaller block hash so every node reaches the same result
/// without trusting peer identity, height claims, or arrival order.
pub fn compare_chain_tips(
    left_work: Work,
    left_hash: BlockHash,
    right_work: Work,
    right_hash: BlockHash,
) -> Ordering {
    left_work
        .cmp(&right_work)
        .then_with(|| right_hash.cmp(&left_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Nonce;
    use crate::crypto::Address;
    use crate::genesis::genesis_block;

    #[test]
    fn rejects_block_that_claims_more_difficulty_than_expected() {
        let genesis = genesis_block().unwrap();
        let mut fork_choice = ForkChoice::new(genesis.hash().unwrap());
        let genesis_hash = fork_choice.insert_block(genesis.clone()).unwrap();
        let miner = Address([1; 20]);
        let forged = Block::from_protocol_transactions(
            Height(1),
            genesis_hash,
            DIFFICULTY_START.saturating_add(1),
            Nonce(0),
            Some(crate::block::EmissionTransaction::new(
                miner,
                crate::consensus::supply::Amount(0),
            )),
            vec![],
        )
        .unwrap();

        assert_eq!(
            fork_choice.insert_block(forged),
            Err(ForkChoiceError::InvalidDifficulty)
        );
        assert_eq!(
            fork_choice.best_tip().map(|node| node.hash),
            Some(genesis_hash)
        );
    }

    #[test]
    fn chain_tip_order_is_work_first_and_deterministic() {
        let low_hash = BlockHash([1; HASH_SIZE]);
        let high_hash = BlockHash([9; HASH_SIZE]);
        let lower_work = Work::from_be_limbs([0, 0, 0, 0, 0, 0, 0, 20]);
        let higher_work = Work::from_be_limbs([0, 0, 0, 0, 0, 0, 0, 21]);

        assert!(compare_chain_tips(higher_work, high_hash, lower_work, low_hash).is_gt());
        assert!(compare_chain_tips(lower_work, low_hash, higher_work, high_hash).is_lt());
        assert!(compare_chain_tips(lower_work, low_hash, lower_work, high_hash).is_gt());
        assert!(compare_chain_tips(lower_work, high_hash, lower_work, low_hash).is_lt());
        assert_eq!(
            compare_chain_tips(lower_work, low_hash, lower_work, low_hash),
            Ordering::Equal
        );
    }

    #[test]
    fn rejects_genesis_other_than_the_configured_hash() {
        let genesis = genesis_block().unwrap();
        let expected = genesis.hash().unwrap();
        let mut fork_choice = ForkChoice::new(expected);
        let mut foreign = genesis;
        foreign.header.nonce = Nonce(foreign.header.nonce.0.saturating_add(1));

        assert_eq!(
            fork_choice.insert_block(foreign),
            Err(ForkChoiceError::UnexpectedGenesis)
        );
        assert!(fork_choice.is_empty());
    }
}
