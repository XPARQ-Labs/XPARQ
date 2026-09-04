use std::{error::Error, fmt};

use xparq_coin::Zeno;
use xparq_crypto::{ADDRESS_SIZE, HASH_SIZE, ProfilePublicKey};
use xparq_transaction::{Recipient, SpendOutput};

pub const STATE_BURN_ALGORITHM: &str =
    "xparq-canonical-archival-and-net-coin-state-growth-burn-v2";
pub const STATE_BURN_RATE_ZENO_PER_WEIGHT: u64 = 1;

// Borsh uses one byte for Option's discriminant and a u32 length prefix for Vec.
const BORSH_OPTION_TAG_BYTES: usize = 1;
const BORSH_VEC_LENGTH_BYTES: usize = core::mem::size_of::<u32>();

/// Canonical encoded size of a non-genesis block containing an emission and no
/// transactions. This is permanent block history, not an arbitrary empty-block
/// penalty. Transaction bytes are charged separately by `ProtocolBurn`.
pub const EMPTY_BLOCK_ARCHIVAL_BYTES: u64 = (3 * HASH_SIZE
    + 2 * core::mem::size_of::<u32>()
    + core::mem::size_of::<u64>() // header nonce
    + core::mem::size_of::<u64>() // block height
    + BORSH_OPTION_TAG_BYTES
    + ADDRESS_SIZE
    + core::mem::size_of::<u64>() // emission subsidy
    + BORSH_VEC_LENGTH_BYTES) as u64;

pub const COIN_UTXO_STATE_WEIGHT: u64 = (xparq_coin::COIN_HASH_SIZE
    + core::mem::size_of::<u64>()
    + 1
    + xparq_common::EXTENSION_HASH_SIZE) as u64;
pub const EMISSION_UTXO_STATE_GROWTH_BURN: Zeno =
    Zeno::from_zeno(COIN_UTXO_STATE_WEIGHT * STATE_BURN_RATE_ZENO_PER_WEIGHT);
pub const EMPTY_BLOCK_ARCHIVAL_BURN: Zeno =
    Zeno::from_zeno(EMPTY_BLOCK_ARCHIVAL_BYTES * STATE_BURN_RATE_ZENO_PER_WEIGHT);
pub const MINER_PROTOCOL_BURN: Zeno = Zeno::from_zeno(
    (EMPTY_BLOCK_ARCHIVAL_BYTES + COIN_UTXO_STATE_WEIGHT) * STATE_BURN_RATE_ZENO_PER_WEIGHT,
);

pub fn profile_key_state_weight(public_key: &ProfilePublicKey) -> Result<u64, StateBurnError> {
    let encoded_value = 1_usize
        .checked_add(core::mem::size_of::<u32>())
        .and_then(|weight| weight.checked_add(public_key.bytes.len()))
        .ok_or(StateBurnError::WeightOverflow)?;
    u64::try_from(
        ADDRESS_SIZE
            .checked_add(encoded_value)
            .ok_or(StateBurnError::WeightOverflow)?,
    )
    .map_err(|_| StateBurnError::WeightOverflow)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateTransitionWeight {
    /// Only newly created spendable outputs. Consumed inputs are historical
    /// transaction bytes and never increase this state-growth component.
    pub created_coin_utxos: u64,
    /// Existing coin UTXOs removed by the transaction. These offset coin UTXO
    /// growth but can never create a negative burn or refund.
    pub consumed_coin_utxos: u64,
    pub created_account_key_weight: u64,
    pub extension_created_weight: u64,
}

impl StateTransitionWeight {
    pub fn state_growth_burn(self) -> Result<Zeno, StateBurnError> {
        let net_coin_utxos = self
            .created_coin_utxos
            .saturating_sub(self.consumed_coin_utxos);
        let created = net_coin_utxos
            .checked_mul(COIN_UTXO_STATE_WEIGHT)
            .and_then(|weight| weight.checked_add(self.created_account_key_weight))
            .and_then(|weight| weight.checked_add(self.extension_created_weight))
            .ok_or(StateBurnError::WeightOverflow)?;
        let burn = created
            .checked_mul(STATE_BURN_RATE_ZENO_PER_WEIGHT)
            .ok_or(StateBurnError::ZenoOverflow)?;
        Ok(Zeno::from_zeno(burn))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolBurn {
    pub archival: Zeno,
    pub state_growth: Zeno,
}

impl ProtocolBurn {
    pub fn for_transaction(
        transition: StateTransitionWeight,
        canonical_transaction_bytes: u64,
    ) -> Result<Self, StateBurnError> {
        let archival = canonical_transaction_bytes
            .checked_mul(STATE_BURN_RATE_ZENO_PER_WEIGHT)
            .ok_or(StateBurnError::ZenoOverflow)?;
        Ok(Self {
            archival: Zeno::from_zeno(archival),
            state_growth: transition.state_growth_burn()?,
        })
    }

    pub fn total(self) -> Result<Zeno, StateBurnError> {
        self.archival
            .checked_add(self.state_growth)
            .ok_or(StateBurnError::ZenoOverflow)
    }
}

pub fn created_coin_output_count(outputs: &[SpendOutput]) -> Result<u64, StateBurnError> {
    u64::try_from(
        outputs
            .iter()
            .filter(|output| output.output != Recipient::Burn)
            .count(),
    )
    .map_err(|_| StateBurnError::WeightOverflow)
}

pub fn validate_exact_burn(
    outputs: &[SpendOutput],
    required: Zeno,
) -> Result<(), StateBurnError> {
    let mut burns = outputs
        .iter()
        .filter(|output| output.output == Recipient::Burn);
    let declared = burns
        .next()
        .map_or(Zeno::from_zeno(0), |output| output.amount);
    if burns.next().is_some() {
        return Err(StateBurnError::MultipleBurnOutputs);
    }
    if declared != required {
        return Err(StateBurnError::IncorrectBurn {
            required: required.as_zeno(),
            declared: declared.as_zeno(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateBurnError {
    WeightOverflow,
    ZenoOverflow,
    MultipleBurnOutputs,
    IncorrectBurn { required: u64, declared: u64 },
}

impl fmt::Display for StateBurnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeightOverflow => formatter.write_str("state transition weight overflow"),
            Self::ZenoOverflow => formatter.write_str("state burn Zeno overflow"),
            Self::MultipleBurnOutputs => formatter.write_str("multiple state burn outputs"),
            Self::IncorrectBurn { required, declared } => write!(
                formatter,
                "incorrect state burn: required {required} zeno, declared {declared} zeno"
            ),
        }
    }
}

impl Error for StateBurnError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumed_coin_state_offsets_created_coin_state_without_refund() {
        let consolidation = StateTransitionWeight {
            created_coin_utxos: 1,
            consumed_coin_utxos: 100,
            ..StateTransitionWeight::default()
        };
        assert_eq!(
            consolidation.state_growth_burn(),
            Ok(Zeno::ZERO)
        );

        let split = StateTransitionWeight {
            created_coin_utxos: 3,
            consumed_coin_utxos: 1,
            ..StateTransitionWeight::default()
        };
        assert_eq!(
            split.state_growth_burn(),
            Ok(Zeno::from_zeno(2 * COIN_UTXO_STATE_WEIGHT))
        );
    }

    #[test]
    fn burn_output_is_not_counted_as_created_ledger_state() {
        let outputs = [
            SpendOutput::new(
                xparq_crypto::Address::ZERO,
                Zeno::from_zeno(1),
            ),
            SpendOutput::burn(Zeno::from_zeno(1)),
        ];

        assert_eq!(created_coin_output_count(&outputs), Ok(1));
    }

    #[test]
    fn charges_canonical_transaction_history_in_addition_to_ledger_state() {
        let transition = StateTransitionWeight {
            created_coin_utxos: 1,
            ..StateTransitionWeight::default()
        };
        let burn = ProtocolBurn::for_transaction(transition, 906).unwrap();

        assert_eq!(burn.archival, Zeno::from_zeno(906));
        assert_eq!(burn.state_growth, Zeno::from_zeno(COIN_UTXO_STATE_WEIGHT));
        assert_eq!(
            burn.total(),
            Ok(Zeno::from_zeno(COIN_UTXO_STATE_WEIGHT + 906))
        );
    }

    #[test]
    fn profile_key_weight_counts_map_key_and_encoded_value() {
        let key = ProfilePublicKey {
            profile: xparq_crypto::SignatureProfile::MlDsa44,
            bytes: vec![7; 32],
        };
        assert_eq!(
            profile_key_state_weight(&key),
            Ok((ADDRESS_SIZE + 1 + 4 + 32) as u64)
        );
    }

    #[test]
    fn miner_burn_charges_block_record_and_emission_utxo() {
        assert_eq!(EMPTY_BLOCK_ARCHIVAL_BURN, Zeno::from_zeno(153));
        assert_eq!(EMISSION_UTXO_STATE_GROWTH_BURN, Zeno::from_zeno(73));
        assert_eq!(MINER_PROTOCOL_BURN, Zeno::from_zeno(226));
    }

    #[test]
    fn exact_burn_cannot_be_missing_underpaid_overpaid_or_duplicated() {
        let required = Zeno::from_zeno(COIN_UTXO_STATE_WEIGHT);
        assert_eq!(
            validate_exact_burn(&[], required),
            Err(StateBurnError::IncorrectBurn {
                required: COIN_UTXO_STATE_WEIGHT,
                declared: 0,
            })
        );
        assert_eq!(
            validate_exact_burn(
                &[SpendOutput::burn(Zeno::from_zeno(
                    COIN_UTXO_STATE_WEIGHT - 1,
                ))],
                required,
            ),
            Err(StateBurnError::IncorrectBurn {
                required: COIN_UTXO_STATE_WEIGHT,
                declared: COIN_UTXO_STATE_WEIGHT - 1,
            })
        );
        assert_eq!(
            validate_exact_burn(
                &[SpendOutput::burn(Zeno::from_zeno(
                    COIN_UTXO_STATE_WEIGHT + 1,
                ))],
                required,
            ),
            Err(StateBurnError::IncorrectBurn {
                required: COIN_UTXO_STATE_WEIGHT,
                declared: COIN_UTXO_STATE_WEIGHT + 1,
            })
        );
        assert_eq!(
            validate_exact_burn(
                &[SpendOutput::burn(required), SpendOutput::burn(required),],
                required,
            ),
            Err(StateBurnError::MultipleBurnOutputs)
        );
        assert_eq!(
            validate_exact_burn(&[SpendOutput::burn(required)], required),
            Ok(())
        );
    }
}
