use crate::block::Block;
use crate::block::{BlockHeight, Height};
use crate::crypto::{
    BlockHash, HASH_SIZE, Hash, ProofOfWorkHash, argon2id_proof_of_work_hash, hash_meets_difficulty,
};

use crate::error::ConsensusError;

const SECOND: u32 = 1;
const MINUTE: u32 = 60 * SECOND;
const HOUR: u32 = 60 * MINUTE;
const DAY: u32 = 24 * HOUR;
pub const BLOCK_TIME: u32 = 5 * MINUTE;
pub const BLOCKS_PER_DAY: u64 = DAY as u64 / BLOCK_TIME as u64;
pub const BLOCKS_PER_YEAR: u64 = 365 * BLOCKS_PER_DAY;
pub const MIN_DIFFICULTY: u32 = 1;
pub const DIFFICULTY_START: u32 = 1;
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 1;
pub const ASERT_HALF_LIFE: u64 = HOUR as u64;
pub const DIFFICULTY_ALGORITHM: &str = "asert-bits-v2";
pub const MAX_FUTURE_TIME: u32 = 2 * MINUTE;

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
        if config.difficulty < MIN_DIFFICULTY {
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

    pub fn validate_genesis_block_at(&self, block: &Block, now: u64) -> Result<(), ConsensusError> {
        block.validate_at(now)?;

        if block.height() != Height(0) || block.previous_hash() != Hash([0; HASH_SIZE]) {
            return Err(ConsensusError::InvalidHeight);
        }

        self.validate_proof_of_work(block)
    }

    pub fn validate_next_block_at(
        &self,
        block: &Block,
        tip_height: BlockHeight,
        tip_hash: BlockHash,
        now: u64,
    ) -> Result<(), ConsensusError> {
        block.validate_at(now)?;
        self.validate_next_block_linkage(block, tip_height, tip_hash)?;
        self.validate_proof_of_work(block)
    }

    pub fn validate_next_block_with_tip_at(
        &self,
        block: &Block,
        tip: &Block,
        now: u64,
    ) -> Result<(), ConsensusError> {
        block.validate_at(now)?;
        self.validate_next_block_linkage(block, tip.height(), tip.hash()?)?;
        if block.timestamp() <= tip.timestamp() {
            return Err(ConsensusError::InvalidTimestamp);
        }
        self.validate_proof_of_work(block)
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

    pub fn validate_candidate_block_at(
        &self,
        block: &Block,
        tip: Option<(BlockHeight, BlockHash)>,
        now: u64,
    ) -> Result<(), ConsensusError> {
        match tip {
            Some((tip_height, tip_hash)) => {
                self.validate_next_block_at(block, tip_height, tip_hash, now)
            }
            None => self.validate_genesis_block_at(block, now),
        }
    }

    pub fn validate_proof_of_work(&self, block: &Block) -> Result<(), ConsensusError> {
        if block.difficulty() != self.difficulty() {
            return Err(ConsensusError::UnexpectedDifficulty);
        }

        self.validate_claimed_proof_of_work(block)
    }

    pub fn validate_proof_of_work_at_difficulty(
        block: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        Self::with_expected_difficulty(expected_difficulty)?.validate_proof_of_work(block)
    }

    pub fn validate_claimed_proof_of_work(&self, block: &Block) -> Result<(), ConsensusError> {
        let hash = proof_of_work_hash(block)?;
        self.validate_proof_of_work_hash_with_difficulty(&hash, block.difficulty())
    }

    pub fn validate_proof_of_work_hash(
        &self,
        hash: &ProofOfWorkHash,
    ) -> Result<(), ConsensusError> {
        self.validate_proof_of_work_hash_with_difficulty(hash, self.difficulty())
    }

    pub fn validate_proof_of_work_hash_with_difficulty(
        &self,
        hash: &ProofOfWorkHash,
        difficulty: u32,
    ) -> Result<(), ConsensusError> {
        if difficulty < MIN_DIFFICULTY {
            return Err(ConsensusError::InvalidDifficulty);
        }

        if hash_meets_difficulty(hash, difficulty) {
            Ok(())
        } else {
            Err(ConsensusError::InsufficientProofOfWork)
        }
    }

    pub fn proof_of_work_hash(&self, block: &Block) -> Result<ProofOfWorkHash, ConsensusError> {
        proof_of_work_hash(block)
    }

    pub fn asert_difficulty(
        &self,
        anchor_difficulty: u32,
        anchor_timestamp: u64,
        anchor_height: BlockHeight,
        block_timestamp: u64,
        block_height: BlockHeight,
    ) -> Result<u32, ConsensusError> {
        if anchor_difficulty < MIN_DIFFICULTY || block_height < anchor_height {
            return Err(ConsensusError::InvalidDifficulty);
        }

        const FRACTION_BITS: i128 = 16;
        const FRACTION_SCALE: i128 = 1_i128 << FRACTION_BITS;
        const ROUNDING: i128 = FRACTION_SCALE / 2;

        let height_delta = block_height.0.saturating_sub(anchor_height.0) as i128;
        let ideal_elapsed = height_delta.saturating_mul(BLOCK_TIME as i128);
        let actual_elapsed = block_timestamp.saturating_sub(anchor_timestamp) as i128;
        let time_error = ideal_elapsed.saturating_sub(actual_elapsed);
        let exponent = time_error
            .saturating_mul(FRACTION_SCALE)
            .checked_div(ASERT_HALF_LIFE as i128)
            .unwrap_or(0);
        let difficulty = (anchor_difficulty as i128)
            .saturating_mul(FRACTION_SCALE)
            .saturating_add(exponent);
        let rounded = if difficulty >= 0 {
            difficulty.saturating_add(ROUNDING) / FRACTION_SCALE
        } else {
            difficulty.saturating_sub(ROUNDING) / FRACTION_SCALE
        };

        Ok(rounded.clamp(MIN_DIFFICULTY as i128, u32::MAX as i128) as u32)
    }
}

fn proof_of_work_hash(block: &Block) -> Result<ProofOfWorkHash, ConsensusError> {
    let header_bytes =
        borsh::to_vec(&block.header).map_err(|_| ConsensusError::ProofOfWorkHashFailed)?;
    argon2id_proof_of_work_hash(&header_bytes).map_err(|error| match error {
        crate::error::CryptoError::InvalidProofOfWorkParameters => {
            ConsensusError::InvalidProofOfWorkParameters
        }
        crate::error::CryptoError::ProofOfWorkHashFailed => ConsensusError::ProofOfWorkHashFailed,
        _ => ConsensusError::ProofOfWorkHashFailed,
    })
}
