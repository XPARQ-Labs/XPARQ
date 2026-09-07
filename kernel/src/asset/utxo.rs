use std::{fmt, str::FromStr};

use crate::common::canonical_bytes;
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;

use crate::asset::{
    ASSET_HASH_SIZE, AssetError, AssetHash, AssetHashParseError, Unit, asset_domain_hash,
    format_hash, parse_hash,
};

const ASSET_SHARE_HASH_CONTEXT: &[u8] = b"XPARQ Native Asset Share";
pub const ASSET_SHARE_HASH_PREFIX: &str = "share:";

/// Owner of a native asset share UTXO.
///
pub type AssetShareOwner = Address;

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
    if value == Unit::ZERO {
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
    pub owner: AssetShareOwner,
}

impl AssetShare {
    pub const fn new(parent: AssetHash, amount: Unit, owner: AssetShareOwner) -> Self {
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

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetShareOutput {
    pub recipient: AssetShareOwner,
    pub amount: Unit,
}
