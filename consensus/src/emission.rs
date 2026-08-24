use crate::block::{Block, BlockHeight, Height};
use crate::consensus::{WBDA_WINDOW, is_wbda_epoch_boundary, reward_first_emission_from_windows};
use static_assertions::const_assert;
use std::{error::Error, fmt};
use xparq_coin::{Amount, COIN};
use xparq_crypto::{Address, Hash, HashDomain, domain_hash};

/// Consensus lower bound for epoch emission.
pub const MIN_BLOCK_EMISSION: u64 = 1_000_000;
/// Consensus upper bound for epoch emission.
pub const MAX_BLOCK_EMISSION: u64 = 10_000_000;
/// One utilization adjustment changes emission by exactly 0.1 XPQ.
pub const BLOCK_EMISSION_STEP: u64 = 100_000;
/// Shared confirmation depth for security-sensitive consensus lifecycles.
pub const STANDARD_CONFIRMATIONS: u64 = 50;
/// Number of blocks before a newly created emission output is spendable.
pub const BLOCK_EMISSION_MATURITY: u64 = STANDARD_CONFIRMATIONS;

const_assert!(MIN_BLOCK_EMISSION == COIN);
const_assert!(MAX_BLOCK_EMISSION == 10 * COIN);
const_assert!(BLOCK_EMISSION_STEP == COIN / 10);

pub const fn initial_block_emission() -> Amount {
    Amount(MIN_BLOCK_EMISSION)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedEmission {
    recipient: Address,
    subsidy: Amount,
    maturity_height: Height,
    origin: Hash,
}

impl ValidatedEmission {
    pub fn recipient(self) -> Address {
        self.recipient
    }

    pub fn subsidy(self) -> Amount {
        self.subsidy
    }

    pub fn maturity_height(self) -> Height {
        self.maturity_height
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
    let maturity_height = Height(block.height().0.saturating_add(BLOCK_EMISSION_MATURITY));
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
        maturity_height,
        origin,
    })
}

/// Calculates the subsidy permitted at `height` from canonical block weights.
///
/// State storage remains outside consensus; callers provide historical header
/// weights through `weight_at`.
pub fn expected_emission_for_height(
    height: BlockHeight,
    parent_emission: Amount,
    mut weight_at: impl FnMut(Height) -> Option<u32>,
) -> Result<Amount, EmissionError> {
    if height.0 <= 1 {
        return Ok(Amount(MIN_BLOCK_EMISSION));
    }

    if !is_wbda_epoch_boundary(height.0) {
        return Ok(parent_emission);
    }

    let has_prior_epoch = height.0 > WBDA_WINDOW as u64 + 1;
    let history_len = if has_prior_epoch {
        WBDA_WINDOW as u64 * 2
    } else {
        WBDA_WINDOW as u64
    };
    let start = height.0 - history_len;
    let weights = (start..height.0)
        .map(|height| {
            let height = Height(height);
            let weight = weight_at(height).ok_or(EmissionError::MissingHistory(height))?;
            usize::try_from(weight).map_err(|_| EmissionError::InvalidBlockWeight(height))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (prior, current) = if has_prior_epoch {
        let (prior, current) = weights.split_at(WBDA_WINDOW);
        (Some(prior), current)
    } else {
        (None, weights.as_slice())
    };
    reward_first_emission_from_windows(parent_emission, prior, current)
        .ok_or(EmissionError::InvalidAdjustment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_boundary_emission_uses_parent_without_loading_history() {
        let parent = Amount(MIN_BLOCK_EMISSION + BLOCK_EMISSION_STEP);
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
        let emission =
            expected_emission_for_height(boundary, Amount(MIN_BLOCK_EMISSION), |height| {
                loaded.push(height);
                Some(MAX_BLOCK_EMISSION as u32)
            })
            .unwrap();
        assert_eq!(loaded.len(), WBDA_WINDOW * 2);
        assert_eq!(
            loaded.first(),
            Some(&Height(boundary.0 - (WBDA_WINDOW * 2) as u64))
        );
        assert_eq!(loaded.last(), Some(&Height(boundary.0 - 1)));
        assert_eq!(emission, Amount(MIN_BLOCK_EMISSION));
    }
}
