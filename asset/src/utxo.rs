use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::{Authority, canonical_bytes};
use xparq_crypto::Address;

use crate::{
    ASSET_HASH_SIZE, AssetError, AssetHash, AssetHashParseError, Unit, asset_domain_hash,
    format_hash, parse_hash,
};

const ASSET_SHARE_HASH_CONTEXT: &[u8] = b"XPARQ Native Asset Share";
pub const ASSET_SHARE_HASH_PREFIX: &str = "share:";

/// Unique identifier of one concrete asset share/UTXO.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct AssetShareHash([u8; ASSET_HASH_SIZE]);

impl AssetShareHash {
    pub fn derive(parent: AssetHash, commitment: [u8; 32], output_index: u32) -> Self {
        Self(asset_domain_hash(
            ASSET_SHARE_HASH_CONTEXT,
            &[parent.as_bytes(), &commitment, &output_index.to_le_bytes()],
        ))
    }

    pub const fn from_bytes(bytes: [u8; ASSET_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ASSET_HASH_SIZE] {
        &self.0
    }
}

pub fn ensure_nonzero_asset_amount(value: Unit) -> Result<(), AssetError> {
    if value == 0 {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}

pub fn ensure_unique_asset_inputs(inputs: &[AssetShareHash]) -> Result<(), AssetError> {
    let mut sorted = inputs.to_vec();
    sorted.sort_unstable();

    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}

pub fn checked_asset_entry_weight<T: BorshSerialize>(
    current: u64,
    key_len: usize,
    value: &T,
) -> Result<u64, AssetError> {
    let value_len = canonical_bytes(value)
        .map_err(|_| AssetError::Encoding)?
        .len();
    let entry = u64::try_from(key_len.checked_add(value_len).ok_or(AssetError::Encoding)?)
        .map_err(|_| AssetError::Encoding)?;

    current.checked_add(entry).ok_or(AssetError::Encoding)
}

impl fmt::Display for AssetShareHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_hash(ASSET_SHARE_HASH_PREFIX, &self.0, formatter)
    }
}

impl FromStr for AssetShareHash {
    type Err = AssetHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_hash(ASSET_SHARE_HASH_PREFIX, value).map(Self)
    }
}

/// One concrete native asset share/UTXO.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct AssetShare {
    pub parent: AssetHash,
    pub amount: Unit,
    pub owner: Authority<Address>,
}

impl AssetShare {
    pub const fn new(parent: AssetHash, amount: Unit, owner: Authority<Address>) -> Self {
        Self {
            parent,
            amount,
            owner,
        }
    }

    pub const fn is_zero(self) -> bool {
        self.amount.is_zero()
    }
}

/// One concrete asset UTXO/object used by the current ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetUtxo {
    pub asset_id: AssetHash,
    pub owner: Authority<Address>,
    pub amount: Unit,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetTransferOutput {
    pub recipient: Authority<Address>,
    pub amount: Unit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ASSET_HASH_PREFIX, derive_asset_hash};

    #[test]
    fn asset_and_share_hashes_are_domain_separated() {
        let fields = [9; ASSET_HASH_SIZE];
        let asset = derive_asset_hash(&[&fields, &0_u32.to_le_bytes()]);
        let parent = AssetHash::from_bytes([7; ASSET_HASH_SIZE]);
        let share = AssetShareHash::derive(parent, fields, 0);

        assert_ne!(&asset, share.as_bytes());
    }

    #[test]
    fn parent_changes_asset_share_hash() {
        let commitment = [9; ASSET_HASH_SIZE];
        let first_parent = AssetHash::from_bytes([1; ASSET_HASH_SIZE]);
        let second_parent = AssetHash::from_bytes([2; ASSET_HASH_SIZE]);

        assert_ne!(
            AssetShareHash::derive(first_parent, commitment, 0),
            AssetShareHash::derive(second_parent, commitment, 0),
        );
    }

    #[test]
    fn asset_and_share_use_distinct_text_prefixes() {
        let bytes = [0xab; ASSET_HASH_SIZE];
        let asset = AssetHash::from_bytes(bytes);
        let share = AssetShareHash::from_bytes(bytes);

        assert!(asset.to_string().starts_with(ASSET_HASH_PREFIX));
        assert!(share.to_string().starts_with(ASSET_SHARE_HASH_PREFIX));
        assert!(asset.to_string().parse::<AssetShareHash>().is_err());
        assert!(share.to_string().parse::<AssetHash>().is_err());
        assert_eq!(asset.to_string().parse(), Ok(asset));
        assert_eq!(share.to_string().parse(), Ok(share));
    }

    #[test]
    fn asset_share_keeps_parent_amount_and_owner() {
        let parent = AssetHash::from_bytes([3; ASSET_HASH_SIZE]);
        let owner = Authority::Address(Address([5; 20]));
        let share = AssetShare::new(parent, Unit::from_units(42), owner);

        assert_eq!(share.parent, parent);
        assert_eq!(share.amount.as_units(), 42);
        assert_eq!(share.owner, owner);
        assert!(!share.is_zero());
    }
}
