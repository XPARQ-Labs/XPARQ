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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_canonical_metadata() {
        let metadata = AssetMetadata::new(
            "Example Asset".to_owned(),
            "EXAMPLE1".to_owned(),
            6,
            Unit::from_units(1_000_000),
            Address([7; 20]),
            None,
        )
        .expect("metadata must be valid");

        assert_eq!(metadata.max_supply_amount().as_units(), 1_000_000);
    }

    #[test]
    fn rejects_noncanonical_metadata() {
        assert!(
            AssetMetadata::new(
                " Example".to_owned(),
                "lower".to_owned(),
                ASSET_DECIMALS_MAX + 1,
                Unit::ZERO,
                Address([7; 20]),
                None,
            )
            .is_err()
        );
    }
}
