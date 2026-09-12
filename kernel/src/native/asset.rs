use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, HASH_SIZE, Hash, HashDomain, HashParseError, domain, format, parse};

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
pub struct Metadata {
    // Rename to Metadata
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: Unit,
    pub creator: Address,
    pub mint_authority: Address,
}

impl Metadata {
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
/// `Asset = H(HashDomain::Asset || Borsh(Metadata))`
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Contract(Hash); // Rename to Contract

impl Contract {
    pub fn derive(metadata: &Metadata) -> Result<Self, AssetError> {
        metadata.validate()?;

        let bytes = borsh::to_vec(metadata).map_err(|_| AssetError::Encoding)?;

        Ok(Self(domain(HashDomain::Asset, &bytes)))
    }

    pub const fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(Hash::from_bytes(bytes))
    }

    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }

    pub const fn into_hash(self) -> Hash {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        self.0.as_bytes()
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0.into_bytes()
    }
}

impl From<Hash> for Contract {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<Contract> for Hash {
    fn from(asset: Contract) -> Self {
        asset.0
    }
}

impl fmt::Display for Contract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format("", &self.0, formatter)
    }
}

impl FromStr for Contract {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse("", value).map(Self)
    }
}

/// Unique identifier of one concrete native Contract share/UTXO.
///
/// A share ID is derived from:
///
/// - asset Contract
/// - transaction/output commitment
/// - output index
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Share(Hash);

impl Share {
    pub fn derive(asset: Contract, commitment: [u8; HASH_SIZE], output_index: u32) -> Self {
        let mut bytes = [0_u8; HASH_SIZE * 2 + 4];

        bytes[..HASH_SIZE].copy_from_slice(asset.as_bytes());

        bytes[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&commitment);

        bytes[HASH_SIZE * 2..].copy_from_slice(&output_index.to_le_bytes());

        Self(domain(HashDomain::Share, &bytes))
    }

    pub const fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(Hash::from_bytes(bytes))
    }

    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }

    pub const fn into_hash(self) -> Hash {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        self.0.as_bytes()
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0.into_bytes()
    }
}

/// Unique identifier of the single-use authority UTXO that permits one Mint.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct MintCapabilityId(Hash);

impl MintCapabilityId {
    pub fn derive(asset: Contract, commitment: [u8; HASH_SIZE]) -> Self {
        let mut bytes = [0_u8; HASH_SIZE * 2];
        bytes[..HASH_SIZE].copy_from_slice(asset.as_bytes());
        bytes[HASH_SIZE..].copy_from_slice(&commitment);
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
    pub asset: Contract,
    pub authority: Address,
}

impl From<Hash> for Share {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<Share> for Hash {
    fn from(share: Share) -> Self {
        share.0
    }
}

impl fmt::Display for Share {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format("", &self.0, formatter)
    }
}

impl FromStr for Share {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse("", value).map(Self)
    }
}

#[cfg(test)]
mod identifier_tests {
    use super::*;

    #[test]
    fn asset_and_share_text_are_unprefixed_hex() {
        let encoded = "cd".repeat(HASH_SIZE);
        let asset = Contract::from_bytes([0xcd; HASH_SIZE]);
        let share = Share::from_bytes([0xcd; HASH_SIZE]);

        assert_eq!(asset.to_string(), encoded);
        assert_eq!(share.to_string(), encoded);
        assert_eq!(encoded.parse::<Contract>(), Ok(asset));
        assert_eq!(encoded.parse::<Share>(), Ok(share));
        assert!(format!("asset:{encoded}").parse::<Contract>().is_err());
        assert!(format!("share:{encoded}").parse::<Share>().is_err());
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
    pub asset: Contract,
    pub amount: Unit,
}

impl AssetShare {
    pub const fn new(asset: Contract, amount: Unit) -> Self {
        Self { asset, amount }
    }

    pub const fn is_zero(self) -> bool {
        self.amount.is_zero()
    }
}

/// Transaction output that creates a new native asset share.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetOutput {
    pub recipient: Address,
    pub amount: Unit,
}

impl AssetOutput {
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
