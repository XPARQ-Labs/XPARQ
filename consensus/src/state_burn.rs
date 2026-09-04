use std::{error::Error, fmt};

use xparq_coin::Amount;
use xparq_crypto::{ADDRESS_SIZE, ProfilePublicKey};
use xparq_transaction::{Recipient, SpendOutput};

pub const STATE_BURN_ALGORITHM: &str = "xparq-canonical-archival-and-state-growth-burn";
pub const STATE_BURN_RATE_ZENO_PER_WEIGHT: u64 = 1;
/// Canonical encoded size of an empty non-genesis block with one emission.
pub const EMPTY_BLOCK_ARCHIVAL_BYTES: u64 = 153;

pub const COIN_UTXO_STATE_WEIGHT: u64 = (xparq_coin::COIN_HASH_SIZE
    + core::mem::size_of::<u64>()
    + 1
    + xparq_common::EXTENSION_HASH_SIZE) as u64;
pub const EMISSION_UTXO_STATE_GROWTH_BURN: Amount =
    Amount::from_zeno(COIN_UTXO_STATE_WEIGHT * STATE_BURN_RATE_ZENO_PER_WEIGHT);
pub const EMPTY_BLOCK_ARCHIVAL_BURN: Amount =
    Amount::from_zeno(EMPTY_BLOCK_ARCHIVAL_BYTES * STATE_BURN_RATE_ZENO_PER_WEIGHT);
pub const MINER_PROTOCOL_BURN: Amount = Amount::from_zeno(
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
    pub created_coin_utxos: u64,
    pub created_account_key_weight: u64,
    pub extension_created_weight: u64,
}

impl StateTransitionWeight {
    pub fn state_growth_burn(self) -> Result<Amount, StateBurnError> {
        let created = self
            .created_coin_utxos
            .checked_mul(COIN_UTXO_STATE_WEIGHT)
            .and_then(|weight| weight.checked_add(self.created_account_key_weight))
            .and_then(|weight| weight.checked_add(self.extension_created_weight))
            .ok_or(StateBurnError::WeightOverflow)?;
        let burn = created
            .checked_mul(STATE_BURN_RATE_ZENO_PER_WEIGHT)
            .ok_or(StateBurnError::AmountOverflow)?;
        Ok(Amount::from_zeno(burn))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolBurn {
    pub archival: Amount,
    pub state_growth: Amount,
}

impl ProtocolBurn {
    pub fn for_transaction(
        transition: StateTransitionWeight,
        canonical_transaction_bytes: u64,
    ) -> Result<Self, StateBurnError> {
        let archival = canonical_transaction_bytes
            .checked_mul(STATE_BURN_RATE_ZENO_PER_WEIGHT)
            .ok_or(StateBurnError::AmountOverflow)?;
        Ok(Self {
            archival: Amount::from_zeno(archival),
            state_growth: transition.state_growth_burn()?,
        })
    }

    pub fn total(self) -> Result<Amount, StateBurnError> {
        self.archival
            .checked_add(self.state_growth)
            .ok_or(StateBurnError::AmountOverflow)
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
    required: Amount,
) -> Result<(), StateBurnError> {
    let mut burns = outputs
        .iter()
        .filter(|output| output.output == Recipient::Burn);
    let declared = burns
        .next()
        .map_or(Amount::from_zeno(0), |output| output.amount);
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
    AmountOverflow,
    MultipleBurnOutputs,
    IncorrectBurn { required: u64, declared: u64 },
}

impl fmt::Display for StateBurnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeightOverflow => formatter.write_str("state transition weight overflow"),
            Self::AmountOverflow => formatter.write_str("state burn amount overflow"),
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
    fn charges_every_created_state_entry_without_input_credit() {
        let replacement = StateTransitionWeight {
            created_coin_utxos: 1,
            ..StateTransitionWeight::default()
        };
        assert_eq!(
            replacement.state_growth_burn(),
            Ok(Amount::from_zeno(COIN_UTXO_STATE_WEIGHT))
        );
    }

    #[test]
    fn charges_canonical_transaction_history_in_addition_to_ledger_state() {
        let transition = StateTransitionWeight {
            created_coin_utxos: 1,
            ..StateTransitionWeight::default()
        };
        let burn = ProtocolBurn::for_transaction(transition, 906).unwrap();

        assert_eq!(burn.archival, Amount::from_zeno(906));
        assert_eq!(burn.state_growth, Amount::from_zeno(COIN_UTXO_STATE_WEIGHT));
        assert_eq!(
            burn.total(),
            Ok(Amount::from_zeno(COIN_UTXO_STATE_WEIGHT + 906))
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
        assert_eq!(EMPTY_BLOCK_ARCHIVAL_BURN, Amount::from_zeno(153));
        assert_eq!(EMISSION_UTXO_STATE_GROWTH_BURN, Amount::from_zeno(73));
        assert_eq!(MINER_PROTOCOL_BURN, Amount::from_zeno(226));
    }

    #[test]
    fn exact_burn_cannot_be_missing_underpaid_overpaid_or_duplicated() {
        let required = Amount::from_zeno(COIN_UTXO_STATE_WEIGHT);
        assert_eq!(
            validate_exact_burn(&[], required),
            Err(StateBurnError::IncorrectBurn {
                required: COIN_UTXO_STATE_WEIGHT,
                declared: 0,
            })
        );
        assert_eq!(
            validate_exact_burn(
                &[SpendOutput::burn(Amount::from_zeno(
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
                &[SpendOutput::burn(Amount::from_zeno(
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
