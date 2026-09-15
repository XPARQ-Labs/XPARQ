use crate::{
    blockchain::{Block, Chain},
    common::Height,
    consensus::{
        ConsensusError, PoWTarget, ValidatedEmission, authorize_emission,
        expected_difficulty_for_height, verify_pow,
    },
};

use crypto::{BlockHash, HASH_SIZE, Hash, PoWHash, PoWMemory};

pub const GENESIS_TARGET_BITS: u32 = crate::blockchain::GENESIS_TARGET_BITS;

pub const TARGET_BITS_START: u32 = 0x207f_ffff;

pub trait ApplyBlockState {
    type Error: From<ConsensusError>;

    fn consensus_chain(&self) -> &Chain;

    fn commit_validated_block(&mut self, block: ValidatedBlock) -> Result<(), Self::Error>;
}

pub fn apply_block<State>(state: &mut State, block: Block) -> Result<(), State::Error>
where
    State: ApplyBlockState,
{
    if !state.consensus_chain().has_blocks() {
        return Err(ConsensusError::GenesisRequired.into());
    }

    let validated = validate_block_for_apply(&block, state.consensus_chain())?;

    state.commit_validated_block(validated)
}

pub fn apply_genesis<State>(
    state: &mut State,
    block: Block,
    expected_hash: BlockHash,
) -> Result<(), State::Error>
where
    State: ApplyBlockState,
{
    if state.consensus_chain().has_blocks() {
        return Err(ConsensusError::InvalidHeight.into());
    }

    Consensus::with_default_config().validate_genesis_block(&block)?;

    if block.hash().map_err(|_| ConsensusError::Serialization)? != expected_hash {
        return Err(ConsensusError::WrongGenesis.into());
    }

    let validated = validate_for_apply(&block, state.consensus_chain(), true)?;

    state.commit_validated_block(validated)
}

#[derive(Clone, Debug)]
pub struct ValidatedBlock {
    block: Block,
    emission: Option<ValidatedEmission>,
}

impl ValidatedBlock {
    pub fn block(&self) -> &Block {
        &self.block
    }

    pub const fn emission(&self) -> Option<ValidatedEmission> {
        self.emission
    }

    pub fn into_block(self) -> Block {
        self.block
    }
}

pub fn validate_block_for_apply(
    block: &Block,
    chain: &Chain,
) -> Result<ValidatedBlock, ConsensusError> {
    validate_for_apply(block, chain, true)
}

pub fn validate_candidate_for_apply(
    block: &Block,
    chain: &Chain,
) -> Result<ValidatedBlock, ConsensusError> {
    validate_for_apply(block, chain, false)
}

fn validate_for_apply(
    block: &Block,
    chain: &Chain,
    enforce_pow: bool,
) -> Result<ValidatedBlock, ConsensusError> {
    block.validate_structure()?;

    chain
        .validate_next_block(block)
        .map_err(|error| match error {
            crate::blockchain::ChainError::InvalidHeight
            | crate::blockchain::ChainError::DuplicateBlock => ConsensusError::InvalidHeight,
            _ => ConsensusError::InvalidPreviousHash,
        })?;

    if !block.is_genesis() {
        let expected_difficulty = expected_difficulty(chain, block.height())?;

        if enforce_pow {
            Consensus::validate_pow_at_target_bits(block, expected_difficulty)?;
        } else if block.target_bits() != expected_difficulty {
            return Err(ConsensusError::UnexpectedDifficulty);
        }
    }

    let emission = if block.is_genesis() {
        None
    } else {
        Some(authorize_emission(block)?)
    };

    Ok(ValidatedBlock {
        block: block.clone(),
        emission,
    })
}

fn expected_difficulty(chain: &Chain, height: Height) -> Result<u32, ConsensusError> {
    if height.0 == 0 {
        return Ok(GENESIS_TARGET_BITS);
    }

    let parent = chain
        .block(&Height(height.0 - 1))
        .ok_or(ConsensusError::InvalidPreviousHash)?;

    expected_difficulty_for_height(height.0, parent.target_bits(), |height| {
        chain
            .block(&Height(height))
            .ok_or(ConsensusError::InvalidPreviousHash)?
            .block_weight()
            .try_into()
            .map_err(|_| ConsensusError::InvalidDifficulty)
    })?
    .ok_or(ConsensusError::InvalidDifficulty)
}

pub fn expected_next_difficulty(chain: &Chain) -> Result<u32, ConsensusError> {
    let height = Height(
        chain
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );

    expected_difficulty(chain, height)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusConfig {
    target_bits: u32,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            target_bits: TARGET_BITS_START,
        }
    }
}

impl ConsensusConfig {
    pub const fn new(target_bits: u32) -> Self {
        Self { target_bits }
    }

    pub const fn target_bits(&self) -> u32 {
        self.target_bits
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consensus {
    config: ConsensusConfig,
}

impl Consensus {
    pub fn new(config: ConsensusConfig) -> Result<Self, ConsensusError> {
        if PoWTarget::from_compact(config.target_bits).is_none() {
            return Err(ConsensusError::InvalidDifficulty);
        }

        Ok(Self { config })
    }

    pub const fn with_default_config() -> Self {
        Self {
            config: ConsensusConfig {
                target_bits: TARGET_BITS_START,
            },
        }
    }

    pub fn with_expected_target_bits(expected_target_bits: u32) -> Result<Self, ConsensusError> {
        Self::new(ConsensusConfig::new(expected_target_bits))
    }

    pub const fn config(&self) -> ConsensusConfig {
        self.config
    }

    pub const fn target_bits(&self) -> u32 {
        self.config.target_bits()
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
        tip_height: Height,
        tip_hash: BlockHash,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;

        self.validate_next_block_linkage(block, tip_height, tip_hash)?;

        Self::validate_pow_at_target_bits(block, expected_difficulty)
    }

    pub fn validate_next_block_with_tip(
        &self,
        block: &Block,
        tip: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        let tip_hash = tip.hash().map_err(|_| ConsensusError::Serialization)?;

        self.validate_next_block(block, tip.height(), tip_hash, expected_difficulty)
    }

    pub(crate) fn validate_next_block_linkage(
        &self,
        block: &Block,
        tip_height: Height,
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
        tip: Option<(Height, BlockHash)>,
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
        if block.target_bits() != self.target_bits() {
            return Err(ConsensusError::UnexpectedDifficulty);
        }

        self.validate_claimed_pow(block)
    }

    pub fn validate_pow_at_target_bits(
        block: &Block,
        expected_target_bits: u32,
    ) -> Result<(), ConsensusError> {
        if block.target_bits() != expected_target_bits {
            return Err(ConsensusError::UnexpectedDifficulty);
        }

        Self::with_expected_target_bits(expected_target_bits)?.validate_claimed_pow(block)
    }

    pub fn validate_claimed_pow(&self, block: &Block) -> Result<(), ConsensusError> {
        verify_pow(&block.header, block.target_bits())
    }

    pub fn validate_pow_hash(&self, hash: &PoWHash) -> Result<(), ConsensusError> {
        self.validate_pow_hash_with_target_bits(hash, self.target_bits())
    }

    pub fn validate_pow_hash_with_target_bits(
        &self,
        hash: &PoWHash,
        target_bits: u32,
    ) -> Result<(), ConsensusError> {
        let target =
            PoWTarget::from_compact(target_bits).ok_or(ConsensusError::InvalidDifficulty)?;

        if target.meets(hash) {
            Ok(())
        } else {
            Err(ConsensusError::InsufficientPoW)
        }
    }

    pub fn pow_hash(&self, block: &Block) -> Result<PoWHash, ConsensusError> {
        crate::consensus::calculate_work(&block.header)
    }

    pub fn pow_hash_with_memory(
        &self,
        block: &Block,
        memory: &mut PoWMemory,
    ) -> Result<PoWHash, ConsensusError> {
        crate::consensus::calculate_work_with_memory(&block.header, memory)
    }
}
