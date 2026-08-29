use crate::block::Block;
use crate::block::{Height, MAX_BLOCK_WEIGHT};
use crate::consensus::{
    Consensus, GENESIS_DIFFICULTY, MAX_DIFFICULTY, MIN_DIFFICULTY, expected_difficulty_for_height,
};
#[cfg(test)]
use crate::consensus::{DIFFICULTY_START, WBDA_WINDOW, next_difficulty_from_window};
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
    pub height: Height,
    pub work: Work,
    pub cumulative_work: Work,
    pub weight: u64,
    pub cumulative_weight: u64,
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
        block
            .validate_structure()
            .map_err(ForkChoiceError::InvalidBlock)?;
        let hash = block.hash().map_err(ForkChoiceError::Serialization)?;
        if self.nodes.contains_key(&hash) {
            return Err(ForkChoiceError::DuplicateBlock);
        }

        if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&block.difficulty()) {
            return Err(ForkChoiceError::InvalidDifficulty);
        }
        if !block.is_genesis()
            && (block.header.block_weight == 0
                || block.header.block_weight as usize > MAX_BLOCK_WEIGHT)
        {
            return Err(ForkChoiceError::InvalidHeader);
        }

        let parent = BlockHash(block.previous_hash().0);
        let (parent_work, parent_weight) = if block.height() == Height(0) {
            if hash != self.expected_genesis {
                return Err(ForkChoiceError::UnexpectedGenesis);
            }
            if parent != Hash([0; HASH_SIZE]) {
                return Err(ForkChoiceError::MissingParent);
            }
            (Work::ZERO, 0)
        } else {
            let parent_node = self
                .nodes
                .get(&parent)
                .ok_or(ForkChoiceError::MissingParent)?;
            if block.height().0 != parent_node.height.0.saturating_add(1) {
                return Err(ForkChoiceError::InvalidHeight);
            }
            (parent_node.cumulative_work, parent_node.cumulative_weight)
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
        let weight = if block.is_genesis() {
            0
        } else {
            u64::from(block.block_weight())
        };
        let cumulative_weight = parent_weight.saturating_add(u64::from(weight));
        let node = BlockNode {
            height: block.height(),
            parent,
            hash,
            work,
            cumulative_work,
            weight,
            cumulative_weight,
            block,
        };

        self.nodes.insert(hash, node);
        self.update_best_tip(hash);
        Ok(hash)
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

    pub fn ancestor_hash_at_height(&self, hash: BlockHash, height: Height) -> Option<BlockHash> {
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

    fn update_best_tip(&mut self, candidate_hash: BlockHash) {
        let Some(candidate) = self.nodes.get(&candidate_hash) else {
            return;
        };

        let should_update = match self.best_tip.and_then(|hash| self.nodes.get(&hash)) {
            None => true,
            Some(best) => compare_chain_tips(
                candidate.cumulative_work,
                candidate.cumulative_weight,
                candidate.hash,
                best.cumulative_work,
                best.cumulative_weight,
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
            return Ok(GENESIS_DIFFICULTY);
        }
        let parent_node = self
            .nodes
            .get(&parent)
            .ok_or(ForkChoiceError::MissingParent)?;
        expected_difficulty_for_height(
            block.height().0,
            parent_node.block.difficulty(),
            |height| {
                self.ancestor_at_height(parent, Height(height))
                    .ok_or(ForkChoiceError::MissingParent)?
                    .block
                    .block_weight()
                    .try_into()
                    .map_err(|_| ForkChoiceError::InvalidDifficulty)
            },
        )?
        .ok_or(ForkChoiceError::InvalidDifficulty)
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
    InvalidBlock(crate::block::BlockError),
    InvalidDifficulty,
    InvalidHeader,
    InvalidProofOfWork(crate::error::ConsensusError),
    InvalidHeight,
    MissingParent,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBlock => f.write_str("block already exists in fork graph"),
            Self::UnexpectedGenesis => {
                f.write_str("fork graph genesis does not match the configured chain")
            }
            Self::InvalidBlock(error) => write!(f, "fork graph block is invalid: {error}"),
            Self::InvalidDifficulty => f.write_str("block difficulty is invalid for its branch"),
            Self::InvalidHeader => f.write_str("block header fields are outside consensus bounds"),
            Self::InvalidProofOfWork(error) => write!(f, "block proof of work is invalid: {error}"),
            Self::InvalidHeight => f.write_str("block height does not follow its parent"),
            Self::MissingParent => f.write_str("block parent is missing from fork graph"),
            Self::Serialization(error) => write!(f, "fork graph encoding failed: {error}"),
        }
    }
}

impl Error for ForkChoiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidProofOfWork(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

pub fn block_work(difficulty: u32) -> Work {
    // `difficulty` is already the branch-local WBDA result validated by the
    // caller. Applying another utilization multiplier here would count WBDA
    // twice and let block weight distort fork choice independently of PoW.
    Work::pow2(difficulty)
}

/// Consensus ordering for valid chain tips.
///
/// Greater locally-computed cumulative work wins. Cumulative canonical block
/// weight only breaks an exact work tie; it can never compensate for less PoW.
/// If both totals tie, the numerically smaller block hash wins so every node
/// reaches the same result without trusting peer identity or arrival order.
pub fn compare_chain_tips(
    left_work: Work,
    left_weight: u64,
    left_hash: BlockHash,
    right_work: Work,
    right_weight: u64,
    right_hash: BlockHash,
) -> Ordering {
    left_work
        .cmp(&right_work)
        .then_with(|| left_weight.cmp(&right_weight))
        .then_with(|| right_hash.cmp(&left_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Nonce;
    use crate::crypto::Address;

    #[test]
    fn rejects_block_that_claims_more_difficulty_than_expected() {
        let genesis = Block::genesis().unwrap();
        let mut fork_choice = ForkChoice::new(genesis.hash().unwrap());
        let genesis_hash = fork_choice.insert_block(genesis.clone()).unwrap();
        let miner = Address([1; crate::crypto::ADDRESS_SIZE]);
        let forged = Block::from_protocol_transactions(
            Height(1),
            genesis_hash,
            DIFFICULTY_START.saturating_add(1),
            Nonce(0),
            Some(crate::block::Emission::new(
                miner,
                xparq_coin::Amount::from_zeno(0),
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

        assert!(compare_chain_tips(higher_work, 0, high_hash, lower_work, 99, low_hash).is_gt());
        assert!(compare_chain_tips(lower_work, 99, low_hash, higher_work, 0, high_hash).is_lt());
        assert!(compare_chain_tips(lower_work, 2, high_hash, lower_work, 1, low_hash).is_gt());
        assert!(compare_chain_tips(lower_work, 1, low_hash, lower_work, 2, high_hash).is_lt());
        assert!(compare_chain_tips(lower_work, 1, low_hash, lower_work, 1, high_hash).is_gt());
        assert!(compare_chain_tips(lower_work, 1, high_hash, lower_work, 1, low_hash).is_lt());
        assert_eq!(
            compare_chain_tips(lower_work, 1, low_hash, lower_work, 1, low_hash),
            Ordering::Equal
        );
    }

    #[test]
    fn wbda_adjusted_difficulty_drives_cumulative_work_fork_choice() {
        let base_difficulty = DIFFICULTY_START;
        let low_utilization_window = vec![1usize; WBDA_WINDOW];
        let adjusted_difficulty =
            next_difficulty_from_window(base_difficulty, &low_utilization_window).unwrap();

        assert_eq!(adjusted_difficulty, base_difficulty.saturating_add(1));

        // Two blocks at the WBDA-adjusted difficulty carry more PoW than
        // three blocks at the previous difficulty. Height/arrival order must
        // therefore not override the cumulative-work decision.
        let adjusted_branch_work =
            block_work(adjusted_difficulty).saturating_add(block_work(adjusted_difficulty));
        let longer_base_branch_work = block_work(base_difficulty)
            .saturating_add(block_work(base_difficulty))
            .saturating_add(block_work(base_difficulty));

        assert!(adjusted_branch_work > longer_base_branch_work);
        assert!(
            compare_chain_tips(
                adjusted_branch_work,
                0,
                BlockHash([9; HASH_SIZE]),
                longer_base_branch_work,
                u64::MAX,
                BlockHash([1; HASH_SIZE]),
            )
            .is_gt()
        );
    }

    #[test]
    fn rejects_genesis_other_than_the_configured_hash() {
        let genesis = Block::genesis().unwrap();
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
