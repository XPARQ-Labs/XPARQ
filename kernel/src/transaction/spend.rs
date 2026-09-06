use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;

use crate::asset::{
    AssetHash, AssetShareHash, AssetShareOutput, ensure_nonzero_asset_amount,
    ensure_unique_asset_inputs,
};
use crate::coin::{CoinHash, Zeno};
use crate::common::domain_hash;
use crate::transaction::{ChainContext, CoinOutput, IntentError, SpendCommitment};

const SPEND_INTENT_COMMITMENT_CONTEXT: &[u8] = b"XPARQ SpendIntent v2";

/// A user-authorized transfer. Register, mint, and burn remain native asset operations.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Spend {
    Coin {
        inputs: Vec<CoinHash>,
        outputs: Vec<CoinOutput>,
        burn: Zeno,
    },
    Asset {
        asset: AssetHash,
        inputs: Vec<AssetShareHash>,
        outputs: Vec<AssetShareOutput>,
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
        inputs: Vec<CoinHash>,
        outputs: Vec<CoinOutput>,
    ) -> Result<Self, IntentError> {
        Self::coin_with_burn(signer, inputs, outputs, Zeno::ZERO)
    }

    pub fn coin_with_burn(
        signer: Address,
        inputs: Vec<CoinHash>,
        outputs: Vec<CoinOutput>,
        burn: Zeno,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            signer,
            spend: Spend::Coin {
                inputs,
                outputs,
                burn,
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn asset(
        signer: Address,
        asset: AssetHash,
        inputs: Vec<AssetShareHash>,
        outputs: Vec<AssetShareOutput>,
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
            Spend::Coin {
                inputs, outputs, ..
            } => {
                if inputs.is_empty() {
                    return Err(IntentError::EmptyInputs);
                }
                let mut unique = BTreeSet::new();
                if inputs.iter().any(|id| !unique.insert(*id)) {
                    return Err(IntentError::DuplicateInput);
                }
                super::intent::validate_public_outputs(outputs, false)
            }
            Spend::Asset {
                inputs, outputs, ..
            } => {
                ensure_unique_asset_inputs(inputs).map_err(|_| IntentError::InvalidAssetCall)?;
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(IntentError::InvalidAssetCall);
                }
                for output in outputs {
                    ensure_nonzero_asset_amount(output.amount)
                        .map_err(|_| IntentError::InvalidAssetCall)?;
                }
                Ok(())
            }
        }
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        super::intent::chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        Ok(SpendCommitment::from_bytes(domain_hash(
            SPEND_INTENT_COMMITMENT_CONTEXT,
            &[&self.signing_bytes(chain)?],
        )))
    }

    pub fn coin_parts(&self) -> Option<(&[CoinHash], &[CoinOutput], Zeno)> {
        match &self.spend {
            Spend::Coin {
                inputs,
                outputs,
                burn,
            } => Some((inputs, outputs, *burn)),
            Spend::Asset { .. } => None,
        }
    }

    pub fn asset_parts(&self) -> Option<(AssetHash, &[AssetShareHash], &[AssetShareOutput])> {
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
