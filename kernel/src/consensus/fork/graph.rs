use super::{ForkChoiceError, Work, block_work, compare_chain_tips};
use crate::{
    blockchain::{Block, MAX_BLOCK_SIZE},
    common::Height,
    consensus::{Consensus, GENESIS_TARGET_BITS, PoWTarget, expected_difficulty_for_height},
};
use crypto::{BlockHash, HASH_SIZE, Hash};
use std::collections::BTreeMap;
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
            block.target_bits() == GENESIS_TARGET_BITS
        } else {
            PoWTarget::from_compact(block.target_bits()).is_some()
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
            if block.target_bits() != expected_difficulty {
                return Err(ForkChoiceError::InvalidDifficulty);
            }
            Consensus::validate_pow_at_target_bits(&block, expected_difficulty)
                .map_err(ForkChoiceError::InvalidProofOfWork)?;
        }

        let work = if block.is_genesis() {
            Work::ZERO
        } else {
            block_work(expected_difficulty).ok_or(ForkChoiceError::InvalidDifficulty)?
        };
        let cumulative_work = parent_work.saturating_add(work);
        let weight = if block.is_genesis() {
            0
        } else {
            u64::from(block.block_weight())
        };
        let cumulative_weight = parent_weight.saturating_add(weight);
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
            return Ok(GENESIS_TARGET_BITS);
        }
        let parent_node = self
            .nodes
            .get(&parent)
            .ok_or(ForkChoiceError::MissingParent)?;
        expected_difficulty_for_height(
            block.height().0,
            parent_node.block.target_bits(),
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
