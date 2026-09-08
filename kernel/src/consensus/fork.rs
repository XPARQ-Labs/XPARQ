use crate::blockchain::Block;
use crate::blockchain::{Height, MAX_BLOCK_SIZE};
use crate::consensus::{
    Consensus, GENESIS_DIFFICULTY, MAX_DIFFICULTY, MIN_DIFFICULTY, expected_difficulty_for_height,
};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{BlockHash, HASH_SIZE, Hash};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
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
        let hash = block.hash().map_err(|_| ForkChoiceError::Serialization)?;
        if self.nodes.contains_key(&hash) {
            return Err(ForkChoiceError::DuplicateBlock);
        }

        let difficulty_is_valid = if block.is_genesis() {
            block.difficulty() == GENESIS_DIFFICULTY
        } else {
            (MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&block.difficulty())
        };
        if !difficulty_is_valid {
            return Err(ForkChoiceError::InvalidDifficulty);
        }
        if !block.is_genesis()
            && (block.header.block_weight == 0
                || block.header.block_weight as usize > MAX_BLOCK_SIZE)
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

#[derive(Debug)]
pub enum ForkChoiceError {
    DuplicateBlock,
    UnexpectedGenesis,
    InvalidBlock(crate::blockchain::BlockError),
    InvalidDifficulty,
    InvalidHeader,
    InvalidProofOfWork(crate::consensus::ConsensusError),
    InvalidHeight,
    MissingParent,
    Serialization,
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
            Self::Serialization => f.write_str("fork graph encoding failed"),
        }
    }
}

impl Error for ForkChoiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBlock(error) => Some(error),
            Self::InvalidProofOfWork(error) => Some(error),
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

// -----------------------------------------------------------------------------
// Reorganization planning
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    ancestor: BlockHash,
    old_tip: Option<BlockHash>,
    new_tip: BlockHash,
    /// Blocks to revert, ordered from the old tip down to the child of the
    /// common ancestor.
    disconnect: Vec<Block>,
    /// Blocks to connect, ordered from the child of the common ancestor up to
    /// the new tip.
    apply: Vec<Block>,
}

impl ReorgPlan {
    pub fn new(
        ancestor: BlockHash,
        old_tip: Option<BlockHash>,
        new_tip: BlockHash,
        disconnect: Vec<Block>,
        apply: Vec<Block>,
    ) -> Result<Self, ReorgError> {
        validate_disconnect(ancestor, old_tip, &disconnect)?;
        validate_apply(ancestor, new_tip, &apply)?;
        Ok(Self {
            ancestor,
            old_tip,
            new_tip,
            disconnect,
            apply,
        })
    }

    pub fn ancestor(&self) -> BlockHash {
        self.ancestor
    }

    pub fn old_tip(&self) -> Option<BlockHash> {
        self.old_tip
    }

    pub fn new_tip(&self) -> BlockHash {
        self.new_tip
    }

    pub fn disconnect(&self) -> &[Block] {
        &self.disconnect
    }

    pub fn apply(&self) -> &[Block] {
        &self.apply
    }

    pub fn into_branches(self) -> (Vec<Block>, Vec<Block>) {
        (self.disconnect, self.apply)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgError {
    InvalidBranch,
}

impl fmt::Display for ReorgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBranch => f.write_str("reorganization branch is incomplete or invalid"),
        }
    }
}

impl Error for ReorgError {}

pub fn plan_reorg(
    old_tip: Option<BlockHash>,
    fork_choice: &ForkChoice,
    new_tip: BlockHash,
) -> Result<ReorgPlan, ReorgError> {
    let ancestor =
        common_ancestor(old_tip, new_tip, fork_choice).ok_or(ReorgError::InvalidBranch)?;
    let apply = fork_choice
        .branch_from_ancestor(ancestor, new_tip)
        .ok_or(ReorgError::InvalidBranch)?;
    let mut disconnect = fork_choice
        .branch_from_ancestor(ancestor, old_tip.ok_or(ReorgError::InvalidBranch)?)
        .ok_or(ReorgError::InvalidBranch)?;
    disconnect.reverse();

    ReorgPlan::new(ancestor, old_tip, new_tip, disconnect, apply)
}

fn validate_disconnect(
    ancestor: BlockHash,
    old_tip: Option<BlockHash>,
    disconnect: &[Block],
) -> Result<(), ReorgError> {
    if disconnect.is_empty() {
        return (old_tip == Some(ancestor))
            .then_some(())
            .ok_or(ReorgError::InvalidBranch);
    }
    if disconnect.first().and_then(|block| block.hash().ok()) != old_tip {
        return Err(ReorgError::InvalidBranch);
    }
    for pair in disconnect.windows(2) {
        if pair[0].previous_hash() != pair[1].hash().map_err(|_| ReorgError::InvalidBranch)? {
            return Err(ReorgError::InvalidBranch);
        }
    }
    if disconnect
        .last()
        .ok_or(ReorgError::InvalidBranch)?
        .previous_hash()
        != ancestor
    {
        return Err(ReorgError::InvalidBranch);
    }
    Ok(())
}

fn validate_apply(
    ancestor: BlockHash,
    new_tip: BlockHash,
    apply: &[Block],
) -> Result<(), ReorgError> {
    if apply.is_empty() {
        return (new_tip == ancestor)
            .then_some(())
            .ok_or(ReorgError::InvalidBranch);
    }
    let mut expected_parent = ancestor;
    for block in apply {
        if block.previous_hash() != expected_parent {
            return Err(ReorgError::InvalidBranch);
        }
        expected_parent = block.hash().map_err(|_| ReorgError::InvalidBranch)?;
    }
    (expected_parent == new_tip)
        .then_some(())
        .ok_or(ReorgError::InvalidBranch)
}

pub fn common_ancestor(
    old_tip: Option<BlockHash>,
    new_tip: BlockHash,
    fork_choice: &ForkChoice,
) -> Option<BlockHash> {
    let old_ancestors: BTreeSet<_> = fork_choice.ancestor_hashes(old_tip?).into_iter().collect();
    fork_choice
        .ancestor_hashes(new_tip)
        .into_iter()
        .find(|hash| old_ancestors.contains(hash))
}
