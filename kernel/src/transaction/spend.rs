use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{Address, HASH_SIZE, HashDomain, canonical_bytes, domain};

use crate::common::ChainContext;

use crate::{
    monetary::{
        asset::{
            AssetOutput, AssetContract, Share, ensure_nonzero_asset_amount, ensure_unique_asset_inputs,
        },
        coin::{CoinOutput, CoinShare, Zeno},
    },
    transaction::IntentError,
};

/// Canonical semantic commitment for a spend intent.
///
/// Account signatures should use `AccountIntent::authorization_commitment`
/// from the authorization layer. That commitment additionally binds the
/// authorization role.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct SpendIntentCommitment([u8; HASH_SIZE]);

impl SpendIntentCommitment {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

/// An account-authorized transfer.
///
/// Register, mint, and burn remain monetary asset operations.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Spend {
    Coin {
        inputs: Vec<CoinShare>,
        outputs: Vec<CoinOutput>,
    },
    Asset {
        asset: AssetContract,
        inputs: Vec<Share>,
        outputs: Vec<AssetOutput>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SpendIntent {
    pub signer: Address,
    pub spend: Spend,
}

impl SpendIntent {
    pub fn coin(
        signer: Address,
        inputs: Vec<CoinShare>,
        outputs: Vec<CoinOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            signer,
            spend: Spend::Coin { inputs, outputs },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn asset(
        signer: Address,
        asset: AssetContract,
        inputs: Vec<Share>,
        outputs: Vec<AssetOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            signer,
            spend: Spend::Asset {
                asset,
                inputs,
                outputs,
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        match &self.spend {
            Spend::Coin { inputs, outputs } => {
                if inputs.is_empty() {
                    return Err(IntentError::EmptyInputs);
                }
                if outputs.is_empty() {
                    return Err(IntentError::EmptyOutputs);
                }

                let mut unique = BTreeSet::new();
                if inputs.iter().any(|id| !unique.insert(*id)) {
                    return Err(IntentError::DuplicateInput);
                }

                if outputs.iter().any(|output| output.amount == Zeno::ZERO) {
                    return Err(IntentError::ZeroAmount);
                }

                Ok(())
            }
            Spend::Asset {
                inputs, outputs, ..
            } => {
                if inputs.is_empty() {
                    return Err(IntentError::EmptyInputs);
                }
                if outputs.is_empty() {
                    return Err(IntentError::EmptyOutputs);
                }

                ensure_unique_asset_inputs(inputs).map_err(|_| IntentError::InvalidAssetCall)?;

                for output in outputs {
                    ensure_nonzero_asset_amount(output.amount)
                        .map_err(|_| IntentError::InvalidAssetCall)?;
                }

                Ok(())
            }
        }
    }

    /// Canonical bytes of the unsigned SpendIntent semantics.
    pub fn semantic_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        canonical_bytes(&(chain.genesis_hash, self)).map_err(|_| IntentError::Encoding)
    }

    /// Compatibility accessor. New code should use `semantic_bytes()`.
    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.semantic_bytes(chain)
    }

    /// Semantic SpendIntent commitment.
    ///
    /// This identifies the unsigned spend semantics. Account signatures must
    /// use the role-bound `AuthorizationCommitment` instead.
    pub fn semantic_commitment(
        &self,
        chain: ChainContext,
    ) -> Result<SpendIntentCommitment, IntentError> {
        let bytes = self.semantic_bytes(chain)?;
        Ok(SpendIntentCommitment::from_bytes(
            domain(HashDomain::SpendIntent, &bytes).into_bytes(),
        ))
    }

    /// Compatibility accessor. New code should use `semantic_commitment()`.
    pub fn commitment(&self, chain: ChainContext) -> Result<SpendIntentCommitment, IntentError> {
        self.semantic_commitment(chain)
    }

    pub fn coin_parts(&self) -> Option<(&[CoinShare], &[CoinOutput])> {
        match &self.spend {
            Spend::Coin { inputs, outputs } => Some((inputs, outputs)),
            Spend::Asset { .. } => None,
        }
    }

    pub fn asset_parts(&self) -> Option<(AssetContract, &[Share], &[AssetOutput])> {
        match &self.spend {
            Spend::Asset {
                asset,
                inputs,
                outputs,
            } => Some((*asset, inputs, outputs)),
            Spend::Coin { .. } => None,
        }
    }
}

#[cfg(test)]
mod conservation_tests {
    use super::*;
    use crate::monetary::{
        asset::{AssetOutput, AssetContract, Share, Unit},
        coin::{CoinOutput, CoinShare, Zeno},
    };

    fn address(byte: u8) -> Address {
        Address([byte; crypto::ADDRESS_SIZE])
    }

    #[test]
    fn duplicate_coin_inputs_are_rejected_structurally() {
        let input = CoinShare::from_bytes([0x11; HASH16_SIZE]);

        let result = SpendIntent::coin(
            address(1),
            vec![input, input],
            vec![CoinOutput::new(address(2), Zeno::from_zeno(1))],
        );

        assert!(matches!(result, Err(IntentError::DuplicateInput)));
    }

    #[test]
    fn duplicate_asset_inputs_are_rejected_structurally() {
        let input = Share::from_bytes([0x22; HASH16_SIZE]);
        let asset = AssetContract::from_bytes([0x33; HASH16_SIZE]);

        let result = SpendIntent::asset(
            address(1),
            asset,
            vec![input, input],
            vec![AssetOutput::new(address(2), Unit::from_units(1))],
        );

        assert!(matches!(result, Err(IntentError::InvalidAssetCall)));
    }

    #[test]
    fn zero_value_coin_output_is_rejected_structurally() {
        let input = CoinShare::from_bytes([0x44; HASH16_SIZE]);

        let result = SpendIntent::coin(
            address(1),
            vec![input],
            vec![CoinOutput::new(address(2), Zeno::ZERO)],
        );

        assert!(matches!(result, Err(IntentError::ZeroAmount)));
    }

    #[test]
    fn zero_value_asset_output_is_rejected_structurally() {
        let input = Share::from_bytes([0x55; HASH16_SIZE]);
        let asset = AssetContract::from_bytes([0x66; HASH16_SIZE]);

        let result = SpendIntent::asset(
            address(1),
            asset,
            vec![input],
            vec![AssetOutput::new(address(2), Unit::ZERO)],
        );

        assert!(matches!(result, Err(IntentError::InvalidAssetCall)));
    }
}
