use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;

use crate::asset::{AssetError, Unit};

pub const ASSET_NAME_MAX_LEN: usize = 64;
pub const ASSET_SYMBOL_MAX_LEN: usize = 16;
pub const ASSET_DECIMALS_MAX: u8 = 18;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: Unit,
    pub creator: Address,
    pub mint_authority: Option<Address>,
}

impl AssetMetadata {
    pub fn new(
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: Unit,
        creator: Address,
        mint_authority: Option<Address>,
    ) -> Result<Self, AssetError> {
        let metadata = Self {
            name,
            symbol,
            decimals,
            max_supply,
            creator,
            mint_authority,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), AssetError> {
        validate_name(&self.name)?;
        validate_symbol(&self.symbol)?;
        if self.decimals > ASSET_DECIMALS_MAX || self.max_supply.is_zero() {
            return Err(AssetError::InvalidProgram);
        }
        Ok(())
    }

    pub const fn max_supply_amount(&self) -> Unit {
        self.max_supply
    }
}

fn validate_name(name: &str) -> Result<(), AssetError> {
    if name.is_empty()
        || name.len() > ASSET_NAME_MAX_LEN
        || name.trim() != name
        || !name
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(AssetError::InvalidProgram);
    }
    Ok(())
}

fn validate_symbol(symbol: &str) -> Result<(), AssetError> {
    if symbol.is_empty()
        || symbol.len() > ASSET_SYMBOL_MAX_LEN
        || !symbol
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(AssetError::InvalidProgram);
    }
    Ok(())
}