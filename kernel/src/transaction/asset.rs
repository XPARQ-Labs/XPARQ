use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{Address, HASH_SIZE, HashDomain, canonical_bytes, domain};

use crate::native::asset::{
    Asset, AssetError, AssetMetadata, AssetShare, MintCapability, MintCapabilityId, Share, Unit,
    ensure_nonzero_asset_amount, ensure_unique_asset_inputs,
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AssetInstruction {
    Register {
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: Unit,
        initial_mint: Unit,
        mint_authority: Address,
    },
    Mint {
        asset: Asset,
        capability: MintCapabilityId,
        recipient: Address,
        amount: Unit,
    },
    Burn {
        asset: Asset,
        inputs: Vec<Share>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AssetIntent {
    pub instruction: AssetInstruction,
    pub signer: Address,
}

impl AssetIntent {
    pub const fn new(instruction: AssetInstruction, signer: Address) -> Self {
        Self { instruction, signer }
    }

    pub fn asset(&self) -> Result<Asset, AssetError> {
        match &self.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                mint_authority,
                ..
            } => {
                let metadata = AssetMetadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    self.signer,
                    *mint_authority,
                )?;
                Asset::derive(&metadata)
            }
            AssetInstruction::Mint { asset, .. } | AssetInstruction::Burn { asset, .. } => {
                Ok(*asset)
            }
        }
    }

    pub fn commitment(&self, genesis_hash: [u8; HASH_SIZE]) -> Result<[u8; HASH_SIZE], AssetError> {
        self.validate_structure()?;
        let bytes = canonical_bytes(&(genesis_hash, self)).map_err(|_| AssetError::Encoding)?;
        Ok(domain(HashDomain::AssetIntent, &bytes).into_bytes())
    }

    pub fn validate_structure(&self) -> Result<(), AssetError> {
        match &self.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                AssetMetadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    self.signer,
                    *mint_authority,
                )?;

                ensure_nonzero_asset_amount(*initial_mint)?;
                if *initial_mint > *max_supply {
                    return Err(AssetError::InvalidAmount);
                }
            }
            AssetInstruction::Mint { amount, .. } => {
                ensure_nonzero_asset_amount(*amount)?;
            }
            AssetInstruction::Burn { inputs, .. } => {
                if inputs.is_empty() {
                    return Err(AssetError::InvalidProgram);
                }
                ensure_unique_asset_inputs(inputs)?;
            }
        }

        Ok(())
    }

    /// Newly-created canonical state weight. Consumed UTXOs are not counted.
    pub fn created_state_weight(&self) -> Result<u64, AssetError> {
        let mut weight = 0_u64;

        match &self.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                let metadata = AssetMetadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    self.signer,
                    *mint_authority,
                )?;
                let asset = Asset::derive(&metadata)?;

                weight = checked_entry_weight(weight, HASH_SIZE, &metadata)?;
                weight = checked_entry_weight(weight, HASH_SIZE, initial_mint)?;
                weight = checked_entry_weight(
                    weight,
                    HASH_SIZE,
                    &AssetShare {
                        parent: asset,
                        amount: *initial_mint,
                    },
                )?;
                if *mint_authority != Address::ZERO {
                    weight = checked_entry_weight(
                        weight,
                        HASH_SIZE,
                        &MintCapability {
                            asset,
                            authority: *mint_authority,
                        },
                    )?;
                }
            }
            AssetInstruction::Mint {
                asset, amount, ..
            } => {
                weight = checked_entry_weight(
                    weight,
                    HASH_SIZE,
                    &AssetShare {
                        parent: *asset,
                        amount: *amount,
                    },
                )?;
            }
            AssetInstruction::Burn { .. } => {}
        }

        Ok(weight)
    }
}

fn checked_entry_weight<T: BorshSerialize>(
    current: u64,
    key_len: usize,
    value: &T,
) -> Result<u64, AssetError> {
    let value_len = borsh::to_vec(value)
        .map_err(|_| AssetError::Encoding)?
        .len();
    let entry = key_len.checked_add(value_len).ok_or(AssetError::Encoding)?;
    let entry = u64::try_from(entry).map_err(|_| AssetError::Encoding)?;
    current.checked_add(entry).ok_or(AssetError::Encoding)
}
