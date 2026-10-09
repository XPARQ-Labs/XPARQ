use crate::monetary::coin::{CoinOutput, Zeno};
use crypto::{HASH_SIZE, PROGRAM_ID_SIZE};
use static_assertions::const_assert;
use std::{error::Error as StdError, fmt};

pub const STATE_BURN_ALGORITHM: &str = "xparq-canonical-archival-and-net-coin-state-growth-burn";
pub const STATE_BURN_RATE_ZENO_PER_BYTE: u64 = 1;

// Borsh wire widths, not Rust struct sizes (which may contain padding).
const BORSH_U32_BYTES: usize = 4;
const BORSH_U64_BYTES: usize = 8;
const BORSH_OPTION_TAG_BYTES: usize = 1;
const BORSH_OWNER_TAG_BYTES: usize = 1;
const BORSH_VEC_LENGTH_BYTES: usize = BORSH_U32_BYTES;

// Header: previous_hash + merkle_root + state_root (three 32-byte hashes),
// target_bits + block_weight (two u32s), and nonce (u64).
const BLOCK_HEADER_ARCHIVAL_BYTES: usize = 3 * HASH_SIZE + 2 * BORSH_U32_BYTES + BORSH_U64_BYTES;
const BLOCK_HEIGHT_ARCHIVAL_BYTES: usize = BORSH_U64_BYTES;
const BLOCK_EMISSION_ARCHIVAL_BYTES: usize =
    BORSH_OPTION_TAG_BYTES + PROGRAM_ID_SIZE + BORSH_U64_BYTES;

/// Exact canonical Borsh size of a non-genesis block with emission and no operations.
/// Transaction operation bytes are charged separately to their callers.
pub const EMPTY_BLOCK_ARCHIVAL_BYTES: u64 = (BLOCK_HEADER_ARCHIVAL_BYTES
    + BLOCK_HEIGHT_ARCHIVAL_BYTES
    + BLOCK_EMISSION_ARCHIVAL_BYTES
    + BORSH_VEC_LENGTH_BYTES) as u64;

// Every monetary owner encodes one ProgramId. Wallet display identities have
// the same width, but are not a distinct ownership variant.
const_assert!(HASH_SIZE == PROGRAM_ID_SIZE);

/// Exact canonical Borsh key/value size: share ID + Zeno(u64) + Owner(tag + payload).
pub const COIN_UTXO_STATE_WEIGHT: u64 = (crate::monetary::coin::CoinShare::SIZE
    + BORSH_U64_BYTES
    + BORSH_OWNER_TAG_BYTES
    + PROGRAM_ID_SIZE) as u64;

pub const EMISSION_UTXO_STATE_GROWTH_BURN: Zeno =
    Zeno::from_zeno(COIN_UTXO_STATE_WEIGHT * STATE_BURN_RATE_ZENO_PER_BYTE);

pub const EMPTY_BLOCK_ARCHIVAL_BURN: Zeno =
    Zeno::from_zeno(EMPTY_BLOCK_ARCHIVAL_BYTES * STATE_BURN_RATE_ZENO_PER_BYTE);

pub const MINER_PROTOCOL_BURN: Zeno = Zeno::from_zeno(
    (EMPTY_BLOCK_ARCHIVAL_BYTES + COIN_UTXO_STATE_WEIGHT) * STATE_BURN_RATE_ZENO_PER_BYTE,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateTransitionWeight {
    pub created_coin_utxos: u64,
    pub consumed_coin_utxos: u64,
    pub created_state_weight: u64,
}

impl StateTransitionWeight {
    pub fn state_growth_burn(self) -> Result<Zeno, BurnError> {
        let net_coin_utxos = self
            .created_coin_utxos
            .saturating_sub(self.consumed_coin_utxos);

        let created = net_coin_utxos
            .checked_mul(COIN_UTXO_STATE_WEIGHT)
            .and_then(|weight| weight.checked_add(self.created_state_weight))
            .ok_or(BurnError::WeightOverflow)?;

        let burn = created
            .checked_mul(STATE_BURN_RATE_ZENO_PER_BYTE)
            .ok_or(BurnError::ZenoOverflow)?;

        Ok(Zeno::from_zeno(burn))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolBurn {
    pub archival: Zeno,
    pub state_growth: Zeno,
}

impl ProtocolBurn {
    pub fn for_program_call(
        transition: StateTransitionWeight,
        canonical_transaction_bytes: u64,
    ) -> Result<Self, BurnError> {
        let archival = canonical_transaction_bytes
            .checked_mul(STATE_BURN_RATE_ZENO_PER_BYTE)
            .ok_or(BurnError::ZenoOverflow)?;

        Ok(Self {
            archival: Zeno::from_zeno(archival),
            state_growth: transition.state_growth_burn()?,
        })
    }

    pub fn total(self) -> Result<Zeno, BurnError> {
        self.archival
            .checked_add(self.state_growth)
            .ok_or(BurnError::ZenoOverflow)
    }
}

pub fn created_coin_output_count(outputs: &[CoinOutput]) -> Result<u64, BurnError> {
    u64::try_from(outputs.len()).map_err(|_| BurnError::WeightOverflow)
}

pub fn validate_exact_burn(actual: Zeno, required: Zeno) -> Result<(), BurnError> {
    if actual != required {
        return Err(BurnError::IncorrectBurn {
            required: required.as_zeno(),
            actual: actual.as_zeno(),
        });
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BurnError {
    WeightOverflow,
    ZenoOverflow,
    IncorrectBurn { required: u64, actual: u64 },
}

impl fmt::Display for BurnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeightOverflow => formatter.write_str("state transition weight overflow"),

            Self::ZenoOverflow => formatter.write_str("protocol burn Zeno overflow"),

            Self::IncorrectBurn { required, actual } => {
                write!(
                    formatter,
                    "incorrect protocol burn: \
                     required {required} zeno, \
                     actual {actual} zeno"
                )
            }
        }
    }
}

impl StdError for BurnError {}

#[cfg(test)]
mod tests;
