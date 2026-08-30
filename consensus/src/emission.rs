use crate::EMISSION_UTXO_STATE_BURN;
use crate::block::{Block, BlockHeight, Height};
use crate::consensus::{WBDA_WINDOW, is_wbda_epoch_boundary, next_emission_from_window};
use static_assertions::const_assert;
use std::{error::Error, fmt};
use xparq_coin::{Amount, COIN};
use xparq_crypto::{Address, Hash, HashDomain, domain_hash};

pub const MIN_BLOCK_EMISSION: u64 = 50_000;
pub const MAX_BLOCK_EMISSION: u64 = 1_000_000;
pub const BLOCK_EMISSION_START: u64 = 100_000;
pub const BLOCK_EMISSION_STEP: u64 = 10_000;

const_assert!(MIN_BLOCK_EMISSION == COIN / 2);
const_assert!(MAX_BLOCK_EMISSION == 10 * COIN);
const_assert!(BLOCK_EMISSION_START == 1 * COIN);
const_assert!(BLOCK_EMISSION_STEP == COIN / 10);

pub const fn initial_block_emission() -> Amount {
    Amount::from_zeno(BLOCK_EMISSION_START)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedEmission {
    recipient: Address,
    subsidy: Amount,
    miner_reward: Amount,
    state_burn: Amount,
    origin: Hash,
}

impl ValidatedEmission {
    pub fn recipient(self) -> Address {
        self.recipient
    }

    pub fn subsidy(self) -> Amount {
        self.subsidy
    }

    /// Net amount inserted into the miner's emission UTXO.
    pub fn miner_reward(self) -> Amount {
        self.miner_reward
    }

    /// Consensus burn charged for creating the emission UTXO.
    pub fn state_burn(self) -> Amount {
        self.state_burn
    }

    pub fn origin(self) -> Hash {
        self.origin
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmissionError {
    MissingEmission,
    InvalidSubsidy,
    MissingHistory(Height),
    InvalidBlockWeight(Height),
    InvalidAdjustment,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for EmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEmission => f.write_str("block emission is missing"),
            Self::InvalidSubsidy => f.write_str("block emission subsidy is invalid"),
            Self::MissingHistory(height) => {
                write!(f, "missing block history at height {}", height.0)
            }
            Self::InvalidBlockWeight(height) => {
                write!(f, "invalid block weight at height {}", height.0)
            }
            Self::InvalidAdjustment => f.write_str("emission adjustment overflowed"),
            Self::Serialization(error) => write!(f, "emission encoding failed: {error}"),
        }
    }
}

impl Error for EmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) fn authorize_emission(
    block: &Block,
    parent_emission: Amount,
    weight_at: impl FnMut(Height) -> Option<u32>,
) -> Result<ValidatedEmission, EmissionError> {
    let emission = block.emission().ok_or(EmissionError::MissingEmission)?;
    let expected = expected_emission_for_height(block.height(), parent_emission, weight_at)?;
    if emission.subsidy != expected {
        return Err(EmissionError::InvalidSubsidy);
    }
    let state_burn = EMISSION_UTXO_STATE_BURN;
    let miner_reward = emission
        .subsidy
        .checked_sub(state_burn)
        .ok_or(EmissionError::InvalidSubsidy)?;
    let origin = domain_hash(
        HashDomain::XPQCoin,
        &xparq_common::canonical_bytes(&(
            b"emission",
            block.previous_hash(),
            block.height(),
            emission.to,
            emission.subsidy,
        ))
        .map_err(EmissionError::Serialization)?,
    );
    Ok(ValidatedEmission {
        recipient: emission.to,
        subsidy: emission.subsidy,
        miner_reward,
        state_burn,
        origin,
    })
}

/// Calculates the subsidy permitted at `height` from canonical block weights.
///
/// State storage remains outside consensus; callers provide historical header
/// weights through `weight_at`. Moves every epoch in lockstep with
/// `expected_difficulty_for_height` — same completed window, same signal.
pub fn expected_emission_for_height(
    height: BlockHeight,
    parent_emission: Amount,
    mut weight_at: impl FnMut(Height) -> Option<u32>,
) -> Result<Amount, EmissionError> {
    if height.0 <= 1 {
        return Ok(Amount::from_zeno(BLOCK_EMISSION_START));
    }

    if !is_wbda_epoch_boundary(height.0) {
        return Ok(parent_emission);
    }

    let start = height.0 - WBDA_WINDOW as u64;
    let weights = (start..height.0)
        .map(|height| {
            let height = Height(height);
            let weight = weight_at(height).ok_or(EmissionError::MissingHistory(height))?;
            usize::try_from(weight).map_err(|_| EmissionError::InvalidBlockWeight(height))
        })
        .collect::<Result<Vec<_>, _>>()?;
    next_emission_from_window(parent_emission, &weights).ok_or(EmissionError::InvalidAdjustment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DIFFICULTY_START, block::Nonce};

    #[test]
    fn emission_utxo_receives_net_reward_after_state_burn() {
        let genesis = Block::genesis().unwrap();
        let block = Block::from_protocol_transactions(
            Height(1),
            genesis.hash().unwrap(),
            DIFFICULTY_START,
            Nonce(0),
            Some(crate::block::Emission::new(
                Address::ZERO,
                initial_block_emission(),
            )),
            vec![],
        )
        .unwrap();
        let emission = authorize_emission(&block, initial_block_emission(), |_| None).unwrap();

        assert_eq!(emission.subsidy(), initial_block_emission());
        assert_eq!(emission.state_burn(), EMISSION_UTXO_STATE_BURN);
        assert_eq!(
            emission.miner_reward(),
            initial_block_emission()
                .checked_sub(EMISSION_UTXO_STATE_BURN)
                .unwrap()
        );
    }

    #[test]
    fn non_boundary_emission_uses_parent_without_loading_history() {
        let parent = Amount::from_zeno(BLOCK_EMISSION_START + BLOCK_EMISSION_STEP);
        let emission = expected_emission_for_height(Height(2), parent, |_| {
            panic!("non-boundary emission must not load history")
        })
        .unwrap();
        assert_eq!(emission, parent);
    }

    #[test]
    fn boundary_emission_loads_only_the_completed_epoch() {
        let boundary = Height((WBDA_WINDOW * 3) as u64 + 1);
        let mut loaded = Vec::new();
        let emission = expected_emission_for_height(
            boundary,
            Amount::from_zeno(BLOCK_EMISSION_START),
            |height| {
                loaded.push(height);
                Some(crate::WBDA_TARGET_BLOCK_WEIGHT as u32)
            },
        )
        .unwrap();
        assert_eq!(loaded.len(), WBDA_WINDOW);
        assert_eq!(
            loaded.first(),
            Some(&Height(boundary.0 - WBDA_WINDOW as u64))
        );
        assert_eq!(loaded.last(), Some(&Height(boundary.0 - 1)));
        // Full utilization decreases emission by one step from the parent.
        assert_eq!(
            emission,
            Amount::from_zeno(BLOCK_EMISSION_START - BLOCK_EMISSION_STEP)
        );
    }
}
