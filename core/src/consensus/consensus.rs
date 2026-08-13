use crate::block::Block;
use crate::block::{BlockHeight, Height};
use crate::crypto::{BlockHash, HASH_SIZE, Hash, PoWHash};

use crate::error::ConsensusError;

pub const MIN_DIFFICULTY: u32 = 1;
/// A 256-bit PoW output cannot represent a stricter leading-zero target.
pub const MAX_DIFFICULTY: u32 = (crate::crypto::POW_HASH_SIZE * 8) as u32;
/// Compatibility name for the height-zero difficulty. Unlike
/// [`DIFFICULTY_START`], this value belongs to the stable genesis header.
pub const GENESIS_DIFFICULTY: u32 = crate::block::GENESIS_BLOCK_DIFFICULTY;
pub const DIFFICULTY_START: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusConfig {
    difficulty: u32,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            difficulty: DIFFICULTY_START,
        }
    }
}

impl ConsensusConfig {
    pub fn new(difficulty: u32) -> Self {
        Self { difficulty }
    }

    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consensus {
    config: ConsensusConfig,
}

impl Consensus {
    pub fn new(config: ConsensusConfig) -> Result<Self, ConsensusError> {
        if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&config.difficulty) {
            return Err(ConsensusError::InvalidDifficulty);
        }

        Ok(Self { config })
    }

    pub fn with_default_config() -> Self {
        Self {
            config: ConsensusConfig::default(),
        }
    }

    pub fn with_expected_difficulty(expected_difficulty: u32) -> Result<Self, ConsensusError> {
        Self::new(ConsensusConfig::new(expected_difficulty))
    }

    pub fn config(&self) -> ConsensusConfig {
        self.config
    }

    pub fn difficulty(&self) -> u32 {
        self.config.difficulty()
    }

    pub fn validate_genesis_block(&self, block: &Block) -> Result<(), ConsensusError> {
        block.validate_structure()?;

        if block.height() != Height(0) || block.previous_hash() != Hash([0; HASH_SIZE]) {
            return Err(ConsensusError::InvalidHeight);
        }

        Ok(())
    }

    pub fn validate_next_block(
        &self,
        block: &Block,
        tip_height: BlockHeight,
        tip_hash: BlockHash,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;
        self.validate_next_block_linkage(block, tip_height, tip_hash)?;
        Self::validate_pow_at_difficulty(block, expected_difficulty)
    }

    pub fn validate_next_block_with_tip(
        &self,
        block: &Block,
        tip: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;
        self.validate_next_block_linkage(block, tip.height(), tip.hash()?)?;
        Self::validate_pow_at_difficulty(block, expected_difficulty)
    }

    pub(crate) fn validate_next_block_linkage(
        &self,
        block: &Block,
        tip_height: BlockHeight,
        tip_hash: BlockHash,
    ) -> Result<(), ConsensusError> {
        if block.height().0 != tip_height.0.saturating_add(1) {
            return Err(ConsensusError::InvalidHeight);
        }

        if block.previous_hash() != tip_hash {
            return Err(ConsensusError::InvalidPreviousHash);
        }

        Ok(())
    }

    pub fn validate_candidate_block(
        &self,
        block: &Block,
        tip: Option<(BlockHeight, BlockHash)>,
        expected_difficulty: Option<u32>,
    ) -> Result<(), ConsensusError> {
        match tip {
            Some((tip_height, tip_hash)) => self.validate_next_block(
                block,
                tip_height,
                tip_hash,
                expected_difficulty.ok_or(ConsensusError::UnexpectedDifficulty)?,
            ),
            None => self.validate_genesis_block(block),
        }
    }

    pub fn validate_pow(&self, block: &Block) -> Result<(), ConsensusError> {
        if block.difficulty() != self.difficulty() {
            return Err(ConsensusError::UnexpectedDifficulty);
        }

        self.validate_claimed_pow(block)
    }

    pub fn validate_pow_at_difficulty(
        block: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        if block.difficulty() != expected_difficulty {
            return Err(ConsensusError::UnexpectedDifficulty);
        }
        Self::with_expected_difficulty(expected_difficulty)?.validate_claimed_pow(block)
    }

    pub fn validate_proof_of_work_at_difficulty(
        block: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        Self::validate_pow_at_difficulty(block, expected_difficulty)
    }

    pub fn validate_claimed_pow(&self, block: &Block) -> Result<(), ConsensusError> {
        crate::consensus::verify_pow(&block.header, block.difficulty())
    }

    pub fn validate_proof_of_work(&self, block: &Block) -> Result<(), ConsensusError> {
        self.validate_claimed_pow(block)
    }

    pub fn validate_pow_hash(&self, hash: &PoWHash) -> Result<(), ConsensusError> {
        self.validate_pow_hash_with_difficulty(hash, self.difficulty())
    }

    pub fn validate_pow_hash_with_difficulty(
        &self,
        hash: &PoWHash,
        difficulty: u32,
    ) -> Result<(), ConsensusError> {
        if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&difficulty) {
            return Err(ConsensusError::InvalidDifficulty);
        }

        if crate::crypto::hash_meets_difficulty(hash, difficulty) {
            Ok(())
        } else {
            Err(ConsensusError::InsufficientPoW)
        }
    }

    pub fn pow_hash(&self, block: &Block) -> Result<PoWHash, ConsensusError> {
        crate::consensus::calculate_work(&block.header)
    }

    pub fn proof_of_work_hash(&self, block: &Block) -> Result<PoWHash, ConsensusError> {
        self.pow_hash(block)
    }

    pub fn validate_proof_of_work_hash_with_difficulty(
        &self,
        hash: &PoWHash,
        difficulty: u32,
    ) -> Result<(), ConsensusError> {
        self.validate_pow_hash_with_difficulty(hash, difficulty)
    }
}
