#[path = "emission.rs"]
mod emission;
#[path = "wbda.rs"]
mod wbda;

pub(crate) use emission::authorize_emission;
pub use emission::{
    BLOCK_EMISSION_MATURITY, BLOCK_EMISSION_STEP, EmissionError, MAX_BLOCK_EMISSION,
    MIN_BLOCK_EMISSION, STANDARD_CONFIRMATIONS, ValidatedEmission, expected_emission_for_height,
    initial_block_emission,
};
pub use wbda::{
    WBDA_ALGORITHM, WBDA_ALGORITHM as DIFFICULTY_ALGORITHM, WBDA_DIFFICULTY_STEP,
    WBDA_HIGH_UTILIZATION_PPM, WBDA_LOW_UTILIZATION_PPM, WBDA_TARGET_BLOCK_WEIGHT, WBDA_WINDOW,
    WbdaAdjustment, adjustment_for_utilization_ppm, adjustment_for_window, average_block_weight,
    confirmed_difficulty_from_windows, expected_difficulty_for_height,
    expected_difficulty_from_windows, is_wbda_epoch_boundary, next_difficulty_from_window,
    next_emission_from_window, reward_first_emission_from_windows, utilization_ppm,
};

use crate::block::Block;
use crate::{Consensus, ConsensusError};
use xparq_blockchain::Chain;

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
    expected_hash: xparq_crypto::BlockHash,
) -> Result<(), State::Error>
where
    State: ApplyBlockState,
{
    if state.consensus_chain().has_blocks() {
        return Err(ConsensusError::InvalidHeight.into());
    }
    Consensus::with_default_config().validate_genesis_block(&block)?;
    if block.hash().map_err(ConsensusError::from)? != expected_hash {
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

    pub fn emission(&self) -> Option<ValidatedEmission> {
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
            xparq_blockchain::ChainError::InvalidHeight
            | xparq_blockchain::ChainError::DuplicateBlock => ConsensusError::InvalidHeight,
            _ => ConsensusError::InvalidPreviousHash,
        })?;

    if !block.is_genesis() {
        let expected_difficulty = expected_difficulty(chain, block.height())?;
        if enforce_pow {
            Consensus::validate_pow_at_difficulty(block, expected_difficulty)?;
        } else if block.difficulty() != expected_difficulty {
            return Err(ConsensusError::UnexpectedDifficulty);
        }
    }

    let emission = if block.is_genesis() {
        None
    } else {
        let parent_emission = if block.height().0 <= 1 {
            initial_block_emission()
        } else {
            chain
                .block(&xparq_blockchain::Height(block.height().0 - 1))
                .and_then(Block::emission)
                .map(|emission| emission.subsidy)
                .ok_or(ConsensusError::InvalidPreviousHash)?
        };
        Some(authorize_emission(block, parent_emission, |height| {
            chain.header(&height).map(|header| header.block_weight)
        })?)
    };
    Ok(ValidatedBlock {
        block: block.clone(),
        emission,
    })
}

fn expected_difficulty(
    chain: &Chain,
    height: xparq_blockchain::BlockHeight,
) -> Result<u32, ConsensusError> {
    if height.0 == 0 {
        return Ok(crate::GENESIS_DIFFICULTY);
    }
    let parent = chain
        .block(&xparq_blockchain::Height(height.0 - 1))
        .ok_or(ConsensusError::InvalidPreviousHash)?;
    expected_difficulty_for_height(height.0, parent.difficulty(), |height| {
        chain
            .block(&xparq_blockchain::Height(height))
            .ok_or(ConsensusError::InvalidPreviousHash)?
            .block_weight()
            .try_into()
            .map_err(|_| ConsensusError::InvalidDifficulty)
    })?
    .ok_or(ConsensusError::InvalidDifficulty)
}

pub fn expected_next_difficulty(chain: &Chain) -> Result<u32, ConsensusError> {
    let height = xparq_blockchain::Height(
        chain
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    expected_difficulty(chain, height)
}
