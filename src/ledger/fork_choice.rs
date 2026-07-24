use crate::block::Block;
use crate::block::{BlockHeight, Height};
use crate::consensus::{Consensus, DIFFICULTY_START, MIN_DIFFICULTY};
use crate::crypto::{BlockHash, HASH_SIZE, Hash};
use std::collections::BTreeMap;
use std::ops::Add;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Work([u64; 8]);

impl Work {
    pub const ZERO: Self = Self([0; 8]);
    pub const MAX: Self = Self([u64::MAX; 8]);

    pub fn to_be_limbs(self) -> [u64; 8] {
        self.0
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForkChoice {
    nodes: BTreeMap<BlockHash, BlockNode>,
    best_tip: Option<BlockHash>,
}

impl ForkChoice {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_block(&mut self, block: Block) -> Result<BlockHash, ForkChoiceError> {
        let hash = block.hash();
        if self.nodes.contains_key(&hash) {
            return Err(ForkChoiceError::DuplicateBlock);
        }

        if block.difficulty() < MIN_DIFFICULTY {
            return Err(ForkChoiceError::InvalidDifficulty);
        }

        let parent = BlockHash(block.previous_hash().0);
        let parent_work = if block.height() == Height(0) {
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
        Consensus::validate_proof_of_work_at_difficulty(&block, expected_difficulty)
            .map_err(|_| ForkChoiceError::InvalidProofOfWork)?;

        let work = block_work(block.difficulty());
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
            Some(best) => {
                candidate.cumulative_work > best.cumulative_work
                    || (candidate.cumulative_work == best.cumulative_work
                        && candidate.hash < best.hash)
            }
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
        if block.height().0 <= 1 {
            return Ok(DIFFICULTY_START);
        }
        let parent_node = self
            .nodes
            .get(&parent)
            .ok_or(ForkChoiceError::MissingParent)?;
        let anchor = self
            .ancestor_at_height(parent, Height(1))
            .ok_or(ForkChoiceError::MissingParent)?;
        Consensus::with_default_config()
            .asert_difficulty(
                anchor.block.difficulty(),
                anchor.block.timestamp(),
                anchor.height,
                parent_node.block.timestamp(),
                parent_node.height,
            )
            .map_err(|_| ForkChoiceError::InvalidDifficulty)
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
    InvalidDifficulty,
    InvalidProofOfWork,
    InvalidHeight,
    MissingParent,
    UnknownFinalizedBlock,
    FinalizedBlockNotOnBestChain,
}

pub fn block_work(difficulty: u32) -> Work {
    Work::pow2(difficulty)
}
