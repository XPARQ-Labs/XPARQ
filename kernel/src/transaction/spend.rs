use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{Address, HASH_SIZE, HashDomain, canonical_bytes, domain};

use crate::{
    native::{
        asset::{
            AssetOutput, Contract, Share, ensure_nonzero_asset_amount, ensure_unique_asset_inputs,
        },
        coin::{CoinOutput, XPQ, Zeno},
    },
    transaction::IntentError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ChainContext {
    pub genesis_hash: [u8; HASH_SIZE],
}

impl ChainContext {
    pub const fn new(genesis_hash: [u8; HASH_SIZE]) -> Self {
        Self { genesis_hash }
    }
}

/// Canonical commitment signed by an account for a spend intent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct SpendCommitment([u8; HASH_SIZE]);

impl SpendCommitment {
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

/// A account-authorized transfer.
///
/// Register, mint, and burn remain native asset operations.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Spend {
    Coin {
        inputs: Vec<XPQ>,
        outputs: Vec<CoinOutput>,
    },
    Asset {
        asset: Contract,
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
        inputs: Vec<XPQ>,
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
        asset: Contract,
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

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        canonical_bytes(&(chain.genesis_hash, self)).map_err(|_| IntentError::Encoding)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        let bytes = self.signing_bytes(chain)?;
        Ok(SpendCommitment::from_bytes(
            domain(HashDomain::SpendIntent, &bytes).into_bytes(),
        ))
    }

    pub fn coin_parts(&self) -> Option<(&[XPQ], &[CoinOutput])> {
        match &self.spend {
            Spend::Coin { inputs, outputs } => Some((inputs, outputs)),
            Spend::Asset { .. } => None,
        }
    }

    pub fn asset_parts(&self) -> Option<(Contract, &[Share], &[AssetOutput])> {
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
