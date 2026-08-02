use crate::block::Block;
use crate::block::{BlockHeight, Height};
use crate::crypto::{
    BlockHash, HASH_SIZE, Hash, ProofOfWorkHash, argon2id_proof_of_work_hash, hash_meets_difficulty,
};

use crate::error::ConsensusError;

pub const MIN_DIFFICULTY: u32 = 1;
pub const GENESIS_DIFFICULTY: u32 = DIFFICULTY_START;
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
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;
        self.validate_next_block_linkage(block, tip_height, tip_hash)?;
        self.validate_claimed_proof_of_work(block)
    }

    pub fn validate_next_block_with_tip(
        &self,
        block: &Block,
        tip: &Block,
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;
        self.validate_next_block_linkage(block, tip.height(), tip.hash()?)?;
        self.validate_claimed_proof_of_work(block)
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
    ) -> Result<(), ConsensusError> {
        match tip {
            Some((tip_height, tip_hash)) => self.validate_next_block(block, tip_height, tip_hash),
            None => self.validate_genesis_block(block),
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
        if block.difficulty() != expected_difficulty {
            return Err(ConsensusError::UnexpectedDifficulty);
        }
        Self::with_expected_difficulty(expected_difficulty)?.validate_claimed_proof_of_work(block)
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
}

fn proof_of_work_hash(block: &Block) -> Result<ProofOfWorkHash, ConsensusError> {
    #[derive(borsh::BorshSerialize)]
    struct ProofOfWorkPayload<'a> {
        header: &'a crate::block::BlockHeader,
        proof: &'a crate::block::BlockProof,
    }

    let bytes = borsh::to_vec(&ProofOfWorkPayload {
        header: &block.header,
        proof: &block.proof,
    })
    .map_err(|_| ConsensusError::ProofOfWorkHashFailed)?;
    argon2id_proof_of_work_hash(&bytes).map_err(|error| match error {
        crate::error::CryptoError::InvalidProofOfWorkParameters => {
            ConsensusError::InvalidProofOfWorkParameters
        }
        crate::error::CryptoError::ProofOfWorkHashFailed => ConsensusError::ProofOfWorkHashFailed,
        _ => ConsensusError::ProofOfWorkHashFailed,
    })
}
