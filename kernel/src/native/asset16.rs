use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{
    ASSET_SIZE, Address, HASH_SIZE, Hash, HashDomain, HashParseError, SHARE_SIZE, domain, format,
    format_bytes, parse, parse_bytes, truncate_hash,
};

use std::{error::Error, fmt, str::FromStr};

pub const ASSET_NAME_MAX_LEN: usize = 64;
pub const ASSET_SYMBOL_MAX_LEN: usize = 16;
pub const ASSET_DECIMALS_MAX: u8 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetError {
    InvalidAmount,
    InvalidProgram,
    AssetAlreadyExists,
    ShareAlreadyExists,
    UnknownAsset,
    UnknownObject,
    AssetMismatch,
    Unauthorized,
    SupplyOverflow,
    BalanceOverflow,
    InsufficientBalance,
    Encoding,
}

impl fmt::Display for AssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AssetError {}

/// Raw unit amount of one native asset.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Unit(u128);

impl Unit {
    pub const ZERO: Self = Self(0);

    pub const fn from_units(units: u128) -> Self {
        Self(units)
    }

    pub const fn as_units(self) -> u128 {
        self.0
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(units) => Some(Self(units)),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(units) => Some(Self(units)),
            None => None,
        }
    }

    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Immutable definition of one native asset.
///
/// The canonical Borsh encoding of this structure is committed
/// into the corresponding `Asset` identifier.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: Unit,
    pub creator: Address,
    pub mint_authority: Address,
}

impl AssetMetadata {
    pub fn new(
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: Unit,
        creator: Address,
        mint_authority: Address,
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

        if self.decimals > ASSET_DECIMALS_MAX {
            return Err(AssetError::InvalidProgram);
        }

        if self.max_supply.is_zero() {
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

/// Cryptographic identifier of one native asset.
///
/// The source digest is SHA3-256 with `HashDomain::Asset`, then the first
/// `ASSET_SIZE` bytes are used as the canonical asset identifier.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Asset([u8; ASSET_SIZE]);

impl Asset {
    pub const SIZE: usize = ASSET_SIZE;

    pub fn derive(metadata: &AssetMetadata) -> Result<Self, AssetError> {
        metadata.validate()?;

        let bytes = borsh::to_vec(metadata).map_err(|_| AssetError::Encoding)?;
        let hash = domain(HashDomain::Asset, &bytes);

        Ok(Self(truncate_hash::<ASSET_SIZE>(hash)))
    }

    pub fn from_hash(hash: Hash) -> Self {
        Self(truncate_hash::<ASSET_SIZE>(hash))
    }

    pub const fn from_bytes(bytes: [u8; ASSET_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ASSET_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; ASSET_SIZE] {
        self.0
    }
}

impl From<Hash> for Asset {
    fn from(hash: Hash) -> Self {
        Self::from_hash(hash)
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes("", &self.0, formatter)
    }
}

impl FromStr for Asset {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_bytes::<ASSET_SIZE>("", value).map(Self)
    }
}

/// Unique identifier of one concrete native asset share/UTXO.
///
/// A share ID is derived from:
///
/// - parent asset ID
/// - transaction/output commitment
/// - output index
///
/// The source digest is SHA3-256 with `HashDomain::Share`, then the first
/// `SHARE_SIZE` bytes are used as the canonical share identifier.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Share([u8; SHARE_SIZE]);

impl Share {
    pub const SIZE: usize = SHARE_SIZE;

    pub fn derive(parent: Asset, commitment: [u8; HASH_SIZE], output_index: u32) -> Self {
        let mut bytes = [0_u8; ASSET_SIZE + HASH_SIZE + 4];

        bytes[..ASSET_SIZE].copy_from_slice(parent.as_bytes());
        bytes[ASSET_SIZE..ASSET_SIZE + HASH_SIZE].copy_from_slice(&commitment);
        bytes[ASSET_SIZE + HASH_SIZE..].copy_from_slice(&output_index.to_le_bytes());

        let hash = domain(HashDomain::Share, &bytes);
        Self(truncate_hash::<SHARE_SIZE>(hash))
    }

    pub fn from_hash(hash: Hash) -> Self {
        Self(truncate_hash::<SHARE_SIZE>(hash))
    }

    pub const fn from_bytes(bytes: [u8; SHARE_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SHARE_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; SHARE_SIZE] {
        self.0
    }
}

impl From<Hash> for Share {
    fn from(hash: Hash) -> Self {
        Self::from_hash(hash)
    }
}

impl fmt::Display for Share {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_bytes("", &self.0, formatter)
    }
}

impl FromStr for Share {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_bytes::<SHARE_SIZE>("", value).map(Self)
    }
}

/// Unique identifier of the single-use authority UTXO that permits one Mint.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct MintCapabilityId(Hash);

impl MintCapabilityId {
    pub fn derive(asset: Asset, commitment: [u8; HASH_SIZE]) -> Self {
        let mut bytes = [0_u8; ASSET_SIZE + HASH_SIZE];
        bytes[..ASSET_SIZE].copy_from_slice(asset.as_bytes());
        bytes[ASSET_SIZE..].copy_from_slice(&commitment);
        Self(domain(HashDomain::MintCapability, &bytes))
    }

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(Hash::from_bytes(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        self.0.as_bytes()
    }
}

impl fmt::Display for MintCapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format("", &self.0, formatter)
    }
}

impl FromStr for MintCapabilityId {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse("", value).map(Self)
    }
}

/// Single-use mint authority carried in the canonical UTXO set.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintCapability {
    pub asset: Asset,
    pub authority: Address,
}

#[cfg(test)]
mod identifier_tests {
    use super::*;

    #[test]
    fn asset_and_share_text_are_unprefixed_hex() {
        let asset_encoded = "cd".repeat(ASSET_SIZE);
        let share_encoded = "ef".repeat(SHARE_SIZE);
        let asset = Asset::from_bytes([0xcd; ASSET_SIZE]);
        let share = Share::from_bytes([0xef; SHARE_SIZE]);

        assert_eq!(asset.to_string(), asset_encoded);
        assert_eq!(share.to_string(), share_encoded);
        assert_eq!(asset_encoded.parse::<Asset>(), Ok(asset));
        assert_eq!(share_encoded.parse::<Share>(), Ok(share));
        assert!(format!("asset:{asset_encoded}").parse::<Asset>().is_err());
        assert!(format!("share:{share_encoded}").parse::<Share>().is_err());
    }
}

/// One concrete live native asset share.
///
/// `Share` is its unique UTXO identifier, while `AssetShare`
/// contains the live state associated with that identifier.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct AssetShare {
    pub parent: Asset,
    pub amount: Unit,
}

impl AssetShare {
    pub const fn new(parent: Asset, amount: Unit) -> Self {
        Self { parent, amount }
    }

    pub const fn is_zero(self) -> bool {
        self.amount.is_zero()
    }
}

/// Transaction output that creates a new native asset share.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub recipient: Address,
    pub amount: Unit,
}

impl Output {
    pub const fn new(recipient: Address, amount: Unit) -> Self {
        Self { recipient, amount }
    }
}

pub fn ensure_nonzero_asset_amount(value: Unit) -> Result<(), AssetError> {
    if value.is_zero() {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}

pub fn ensure_unique_asset_inputs(inputs: &[Share]) -> Result<(), AssetError> {
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
    let value_len = crypto::canonical_bytes(value)
        .map_err(|_| AssetError::Encoding)?
        .len();
    let entry = u64::try_from(key_len.checked_add(value_len).ok_or(AssetError::Encoding)?)
        .map_err(|_| AssetError::Encoding)?;

    current.checked_add(entry).ok_or(AssetError::Encoding)
}
