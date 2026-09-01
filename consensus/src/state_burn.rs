use std::{error::Error, fmt};

use xparq_coin::Amount;
use xparq_crypto::{ADDRESS_SIZE, QCASH_PUBLIC_KEY_SIZE};
use xparq_transaction::{OutputTarget, SpendOutput};

pub const STATE_BURN_ALGORITHM: &str = "xparq-state-creation-burn-emission-bucket-v2";
pub const STATE_BURN_EMISSION_MULTIPLIER: u64 = 2;

pub const COIN_UTXO_STATE_WEIGHT: u64 =
    (xparq_coin::COIN_ID_SIZE + core::mem::size_of::<u64>() + ADDRESS_SIZE) as u64;
pub const QCASH_UTXO_STATE_WEIGHT: u64 =
    (xparq_coin::COIN_ID_SIZE + core::mem::size_of::<u64>() + QCASH_PUBLIC_KEY_SIZE) as u64;
pub const fn state_burn_rate_for_emission(emission: Amount) -> u64 {
    (emission.as_zeno() / xparq_coin::COIN) * STATE_BURN_EMISSION_MULTIPLIER
}

pub fn emission_utxo_state_burn(emission: Amount) -> Result<Amount, StateBurnError> {
    let burn = COIN_UTXO_STATE_WEIGHT
        .checked_mul(state_burn_rate_for_emission(emission))
        .ok_or(StateBurnError::AmountOverflow)?;
    Ok(Amount::from_zeno(burn))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateTransitionWeight {
    pub created_coin_utxos: u64,
    pub created_qcash_utxos: u64,
    pub extension_created_weight: u64,
}

impl StateTransitionWeight {
    pub fn required_burn(self, emission: Amount) -> Result<Amount, StateBurnError> {
        let created = self
            .created_coin_utxos
            .checked_mul(COIN_UTXO_STATE_WEIGHT)
            .and_then(|weight| {
                self.created_qcash_utxos
                    .checked_mul(QCASH_UTXO_STATE_WEIGHT)
                    .and_then(|qcash| weight.checked_add(qcash))
            })
            .and_then(|weight| weight.checked_add(self.extension_created_weight))
            .ok_or(StateBurnError::WeightOverflow)?;
        let burn = created
            .checked_mul(state_burn_rate_for_emission(emission))
            .ok_or(StateBurnError::AmountOverflow)?;
        Ok(Amount::from_zeno(burn))
    }
}

pub fn created_coin_output_count(outputs: &[SpendOutput]) -> Result<u64, StateBurnError> {
    u64::try_from(
        outputs
            .iter()
            .filter(|output| output.target != OutputTarget::Burn)
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
        .filter(|output| output.target == OutputTarget::Burn);
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
        let emission = Amount::from_zeno(5 * xparq_coin::COIN);
        let replacement = StateTransitionWeight {
            created_coin_utxos: 1,
            ..StateTransitionWeight::default()
        };
        assert_eq!(
            replacement.required_burn(emission),
            Ok(Amount::from_zeno(10 * COIN_UTXO_STATE_WEIGHT))
        );

        let two_outputs = StateTransitionWeight {
            created_qcash_utxos: 2,
            ..StateTransitionWeight::default()
        };
        assert_eq!(
            two_outputs.required_burn(emission),
            Ok(Amount::from_zeno(20 * QCASH_UTXO_STATE_WEIGHT))
        );
    }

    #[test]
    fn emission_floor_selects_two_zeno_buckets() {
        for whole in 1..10_u64 {
            let rate = whole * STATE_BURN_EMISSION_MULTIPLIER;
            assert_eq!(
                state_burn_rate_for_emission(Amount::from_zeno(whole * xparq_coin::COIN)),
                rate
            );
            assert_eq!(
                state_burn_rate_for_emission(Amount::from_zeno(
                    whole * xparq_coin::COIN + 9 * xparq_coin::COIN / 10,
                )),
                rate
            );
        }
        assert_eq!(
            state_burn_rate_for_emission(Amount::from_zeno(10 * xparq_coin::COIN)),
            20
        );
    }

    #[test]
    fn exact_burn_cannot_be_missing_underpaid_overpaid_or_duplicated() {
        let required = Amount::from_zeno(QCASH_UTXO_STATE_WEIGHT);
        assert_eq!(
            validate_exact_burn(&[], required),
            Err(StateBurnError::IncorrectBurn {
                required: QCASH_UTXO_STATE_WEIGHT,
                declared: 0,
            })
        );
        assert_eq!(
            validate_exact_burn(
                &[SpendOutput::burn(Amount::from_zeno(
                    QCASH_UTXO_STATE_WEIGHT - 1,
                ))],
                required,
            ),
            Err(StateBurnError::IncorrectBurn {
                required: QCASH_UTXO_STATE_WEIGHT,
                declared: QCASH_UTXO_STATE_WEIGHT - 1,
            })
        );
        assert_eq!(
            validate_exact_burn(
                &[SpendOutput::burn(Amount::from_zeno(
                    QCASH_UTXO_STATE_WEIGHT + 1,
                ))],
                required,
            ),
            Err(StateBurnError::IncorrectBurn {
                required: QCASH_UTXO_STATE_WEIGHT,
                declared: QCASH_UTXO_STATE_WEIGHT + 1,
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
