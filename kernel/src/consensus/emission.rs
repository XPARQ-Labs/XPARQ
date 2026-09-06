use crate::blockchain::{Block, BlockHeight, Height};
use crate::coin::{XPQ, Zeno};
use crate::consensus::MINER_PROTOCOL_BURN;
use crate::consensus::{WBDA_WINDOW, is_wbda_epoch_boundary, next_emission_from_window};
use crypto::{Address, Hash, HashDomain, domain_hash};
use static_assertions::const_assert;
use std::{error::Error, fmt};

pub const MIN_BLOCK_EMISSION: u64 = 1_000_000;
pub const MAX_BLOCK_EMISSION: u64 = 10_000_000;
pub const BLOCK_EMISSION_START: u64 = 5_000_000;
pub const BLOCK_EMISSION_STEP: u64 = 100_000;

const_assert!(MIN_BLOCK_EMISSION == XPQ::ZENO_PER_COIN);
const_assert!(MAX_BLOCK_EMISSION == 10 * XPQ::ZENO_PER_COIN);
const_assert!(BLOCK_EMISSION_START == 5 * XPQ::ZENO_PER_COIN);
const_assert!(BLOCK_EMISSION_STEP == XPQ::ZENO_PER_COIN / 10);

pub const fn initial_block_emission() -> Zeno {
    Zeno::from_zeno(BLOCK_EMISSION_START)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedEmission {
    recipient: Address,
    subsidy: Zeno,
    miner_emission: Zeno,
    protocol_burn: Zeno,
    origin: Hash,
}

impl ValidatedEmission {
    pub fn recipient(self) -> Address {
        self.recipient
    }

    pub fn subsidy(self) -> Zeno {
        self.subsidy
    }

    /// Net Zeno inserted into the miner's emission UTXO.
    pub fn miner_emission(self) -> Zeno {
        self.miner_emission
    }

    /// Archival burn for the block plus state-growth burn for its emission UTXO.
    pub fn protocol_burn(self) -> Zeno {
        self.protocol_burn
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
    Serialization(crate::consensus::error::CodecError),
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
    parent_emission: Zeno,
    weight_at: impl FnMut(Height) -> Option<u32>,
) -> Result<ValidatedEmission, EmissionError> {
    let emission = block.emission().ok_or(EmissionError::MissingEmission)?;
    let expected = expected_emission_for_height(block.height(), parent_emission, weight_at)?;
    if emission.subsidy != expected {
        return Err(EmissionError::InvalidSubsidy);
    }
    let protocol_burn = MINER_PROTOCOL_BURN;
    let miner_emission = emission
        .subsidy
        .checked_sub(protocol_burn)
        .ok_or(EmissionError::InvalidSubsidy)?;
    let origin = domain_hash(
        HashDomain::XPQCoin,
        &crate::common::canonical_bytes(&(
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
        miner_emission,
        protocol_burn,
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
    parent_emission: Zeno,
    mut weight_at: impl FnMut(Height) -> Option<u32>,
) -> Result<Zeno, EmissionError> {
    if height.0 <= 1 {
        return Ok(Zeno::from_zeno(BLOCK_EMISSION_START));
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