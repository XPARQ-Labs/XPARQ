use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, HASH_SIZE, HashDomain, canonical_bytes, domain};

use crate::native::pool::{
    Liquidity, Pair, PoolAmount, PoolError, PoolHash, PoolShareHash, canonical_pair, ensure_amount,
    ensure_liquidity,
};
use crate::native::{asset::Share, coin::XPQ};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum PoolFunding {
    Coin {
        inputs: Vec<XPQ>,
    },
    Asset {
        asset: crate::native::asset::Asset,
        inputs: Vec<Share>,
    },
}

impl PoolFunding {
    pub const fn pair(&self) -> Pair {
        match self {
            Self::Coin { .. } => Pair::Coin,
            Self::Asset { asset, .. } => Pair::Asset(*asset),
        }
    }

    pub fn validate(&self) -> Result<(), PoolError> {
        let duplicate = match self {
            Self::Coin { inputs } => {
                if inputs.is_empty() {
                    return Err(PoolError::InvalidAmount);
                }
                let mut sorted = inputs.clone();
                sorted.sort_unstable();
                sorted.windows(2).any(|pair| pair[0] == pair[1])
            }
            Self::Asset { inputs, .. } => {
                if inputs.is_empty() {
                    return Err(PoolError::InvalidAmount);
                }
                let mut sorted = inputs.clone();
                sorted.sort_unstable();
                sorted.windows(2).any(|pair| pair[0] == pair[1])
            }
        };
        if duplicate {
            Err(PoolError::InvalidAmount)
        } else {
            Ok(())
        }
    }
}

/// User instruction only; execution and state ownership belong to the ledger layer.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum PoolInstruction {
    Create {
        asset_x: Pair,
        asset_y: Pair,
        amount_x: PoolAmount,
        amount_y: PoolAmount,
        funding_x: PoolFunding,
        funding_y: PoolFunding,
        fee_units: u32,
    },
    AddLiquidity {
        pool: PoolHash,
        amount_x: PoolAmount,
        amount_y: PoolAmount,
        funding_x: PoolFunding,
        funding_y: PoolFunding,
        minimum_liquidity: Liquidity,
    },
    RemoveLiquidity {
        share: PoolShareHash,
        minimum_x: PoolAmount,
        minimum_y: PoolAmount,
    },
    Swap {
        pool: PoolHash,
        input_asset: Pair,
        amount_in: PoolAmount,
        funding: PoolFunding,
        minimum_out: PoolAmount,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct PoolIntent {
    pub signer: Address,
    pub instruction: PoolInstruction,
}

impl PoolIntent {
    pub const fn new(signer: Address, instruction: PoolInstruction) -> Self {
        Self {
            signer,
            instruction,
        }
    }

    pub fn validate_structure(&self) -> Result<(), PoolError> {
        match self.instruction {
            PoolInstruction::Create {
                asset_x,
                asset_y,
                amount_x,
                amount_y,
                ref funding_x,
                ref funding_y,
                fee_units,
            } => {
                canonical_pair(asset_x, asset_y)?;
                ensure_amount(amount_x)?;
                ensure_amount(amount_y)?;
                funding_x.validate()?;
                funding_y.validate()?;
                if funding_x.pair() != asset_x || funding_y.pair() != asset_y {
                    return Err(PoolError::InvalidAmount);
                }
                if fee_units >= crate::native::pool::FEE_DENOMINATOR {
                    return Err(PoolError::InvalidFee);
                }
            }
            PoolInstruction::AddLiquidity {
                amount_x,
                amount_y,
                ref funding_x,
                ref funding_y,
                minimum_liquidity,
                ..
            } => {
                ensure_amount(amount_x)?;
                ensure_amount(amount_y)?;
                ensure_liquidity(minimum_liquidity)?;
                funding_x.validate()?;
                funding_y.validate()?;
            }
            PoolInstruction::RemoveLiquidity { .. } => {}
            PoolInstruction::Swap {
                input_asset,
                amount_in,
                minimum_out,
                ref funding,
                ..
            } => {
                ensure_amount(amount_in)?;
                ensure_amount(minimum_out)?;
                funding.validate()?;
                if funding.pair() != input_asset {
                    return Err(PoolError::InvalidAmount);
                }
            }
        }
        Ok(())
    }

    pub fn commitment(&self, genesis_hash: [u8; HASH_SIZE]) -> Result<[u8; HASH_SIZE], PoolError> {
        self.validate_structure()?;
        let bytes = canonical_bytes(&(genesis_hash, self)).map_err(|_| PoolError::Encoding)?;
        Ok(domain(HashDomain::PoolIntent, &bytes).into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_chain_bound_and_deterministic() {
        let intent = PoolIntent::new(
            Address::ZERO,
            PoolInstruction::Create {
                asset_x: Pair::Coin,
                asset_y: Pair::Asset(crate::native::asset::Asset::from_bytes([1; HASH_SIZE])),
                amount_x: PoolAmount::from_raw(10),
                amount_y: PoolAmount::from_raw(20),
                funding_x: PoolFunding::Coin {
                    inputs: vec![XPQ::from_bytes([2; HASH_SIZE])],
                },
                funding_y: PoolFunding::Asset {
                    asset: crate::native::asset::Asset::from_bytes([1; HASH_SIZE]),
                    inputs: vec![Share::from_bytes([3; HASH_SIZE])],
                },
                fee_units: 300,
            },
        );
        assert_eq!(
            intent.commitment([4; HASH_SIZE]),
            intent.commitment([4; HASH_SIZE])
        );
        assert_ne!(
            intent.commitment([4; HASH_SIZE]),
            intent.commitment([5; HASH_SIZE])
        );
    }
}
