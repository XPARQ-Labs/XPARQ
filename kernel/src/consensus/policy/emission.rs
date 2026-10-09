use super::burn::MINER_PROTOCOL_BURN;
use crate::{blockchain::Block, common::Height, monetary::coin::Zeno};
use crypto::{Hash, HashDomain, ProgramId, canonical_bytes, domain};
use static_assertions::const_assert;
use std::{error::Error as StdError, fmt};

#[cfg(test)]
mod tests;

pub const BLOCK_EMISSION_START: u64 = 156_250_000; // 1.562500 XPQ
pub const MAX_BLOCK_EMISSION: u64 = 5_000_000_000; // 50 XPQ
pub const TAIL_BLOCK_EMISSION: u64 = 78_125_000; // 0.781250 XPQ
pub const EMISSION_RISING_STEPS: u64 = 5;
pub const EMISSION_HALVINGS_TO_TAIL: u64 = 6;

pub const EMISSION_INTERVAL: u64 = 100_000;

const_assert!(BLOCK_EMISSION_START * (1_u64 << EMISSION_RISING_STEPS) == MAX_BLOCK_EMISSION);

const_assert!(MAX_BLOCK_EMISSION / (1_u64 << EMISSION_HALVINGS_TO_TAIL) == TAIL_BLOCK_EMISSION);

pub const fn initial_block_emission() -> Zeno {
    Zeno::from_zeno(BLOCK_EMISSION_START)
}

pub const fn is_emission_epoch_boundary(height: u64) -> bool {
    height > 1 && (height - 1).is_multiple_of(EMISSION_INTERVAL)
}

pub fn block_emission_for_height(height: Height) -> Zeno {
    let completed_intervals = height.0.saturating_sub(1) / EMISSION_INTERVAL;

    let emission = if completed_intervals <= EMISSION_RISING_STEPS {
        // Reverse halving / doubling phase:
        //
        // 1.5625
        // 3.125
        // 6.25
        // 12.5
        // 25
        // 50
        let multiplier = 1_u64 << completed_intervals;

        BLOCK_EMISSION_START
            .saturating_mul(multiplier)
            .min(MAX_BLOCK_EMISSION)
    } else {
        // Normal halving phase after peak.
        let halvings = completed_intervals - EMISSION_RISING_STEPS;

        if halvings >= EMISSION_HALVINGS_TO_TAIL {
            TAIL_BLOCK_EMISSION
        } else {
            (MAX_BLOCK_EMISSION >> halvings).max(TAIL_BLOCK_EMISSION)
        }
    };

    Zeno::from_zeno(emission)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedEmission {
    recipient: ProgramId,
    subsidy: Zeno,
    miner_emission: Zeno,
    protocol_burn: Zeno,
    origin: Hash,
}

impl ValidatedEmission {
    pub const fn recipient(self) -> ProgramId {
        self.recipient
    }

    pub const fn subsidy(self) -> Zeno {
        self.subsidy
    }

    pub const fn miner_emission(self) -> Zeno {
        self.miner_emission
    }

    pub const fn protocol_burn(self) -> Zeno {
        self.protocol_burn
    }

    pub const fn origin(self) -> Hash {
        self.origin
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmissionError {
    MissingEmission,
    InvalidSubsidy,
    Serialization,
}

impl fmt::Display for EmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEmission => f.write_str("block emission is missing"),
            Self::InvalidSubsidy => f.write_str("block emission subsidy is invalid"),
            Self::Serialization => f.write_str("emission encoding failed"),
        }
    }
}

impl StdError for EmissionError {}

pub fn validate_emission(block: &Block) -> Result<ValidatedEmission, EmissionError> {
    authorize_emission(block)
}

/// Derive the emission UTXO origin from block body fields, independent of
/// subsidy validation. Canonical block admission validates the subsidy.
pub fn emission_origin(block: &Block) -> Result<Hash, EmissionError> {
    let emission = block.emission().ok_or(EmissionError::MissingEmission)?;
    let bytes = canonical_bytes(&(
        b"emission",
        block.previous_hash(),
        block.height(),
        emission.to,
        emission.subsidy,
    ))
    .map_err(|_| EmissionError::Serialization)?;
    Ok(domain(HashDomain::Emission, &bytes))
}

pub(crate) fn authorize_emission(block: &Block) -> Result<ValidatedEmission, EmissionError> {
    let emission = block.emission().ok_or(EmissionError::MissingEmission)?;

    let expected = block_emission_for_height(block.height());

    if emission.subsidy != expected {
        return Err(EmissionError::InvalidSubsidy);
    }

    let protocol_burn = MINER_PROTOCOL_BURN;

    let miner_emission = emission
        .subsidy
        .checked_sub(protocol_burn)
        .ok_or(EmissionError::InvalidSubsidy)?;

    let origin = emission_origin(block)?;

    Ok(ValidatedEmission {
        recipient: emission.to,
        subsidy: emission.subsidy,
        miner_emission,
        protocol_burn,
        origin,
    })
}

pub fn expected_emission_for_height(height: Height) -> Zeno {
    block_emission_for_height(height)
}
