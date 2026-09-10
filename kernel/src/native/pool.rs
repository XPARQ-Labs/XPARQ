use std::{error::Error, fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{
    Address, HASH_SIZE, Hash, HashDomain, HashParseError, Height, canonical_bytes, domain, format,
    parse,
};

use super::{
    asset::{Asset, Unit},
    coin::Zeno,
};

/// Denominator for swap fees expressed in parts per 100,000.
///
/// For example, `fee_units = 300` means `300 / 100_000 = 0.30%`.
pub const FEE_DENOMINATOR: u32 = 100_000;

/// One side of a liquidity pair. `Coin` is the native XPQ currency; `Asset`
/// identifies a user-created native asset.
#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum Pair {
    Coin,
    Asset(Asset),
}

/// Raw quantity used internally by the AMM for either side of a pair.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct PoolAmount(u128);

impl PoolAmount {
    pub const ZERO: Self = Self(0);
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }
    pub const fn as_raw(self) -> u128 {
        self.0
    }
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    pub fn into_zeno(self) -> Result<Zeno, PoolError> {
        u64::try_from(self.0)
            .map(Zeno::from_zeno)
            .map_err(|_| PoolError::AmountConversion)
    }
    pub const fn into_unit(self) -> Unit {
        Unit::from_units(self.0)
    }
}

impl From<Zeno> for PoolAmount {
    fn from(value: Zeno) -> Self {
        Self(u128::from(value.as_zeno()))
    }
}

impl From<Unit> for PoolAmount {
    fn from(value: Unit) -> Self {
        Self(value.as_units())
    }
}

/// Fungible LP quantity, separate from coin, asset, and reserve amounts.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Liquidity(u128);

impl Liquidity {
    pub const ZERO: Self = Self(0);
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }
    pub const fn as_raw(self) -> u128 {
        self.0
    }
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    IdenticalPair,
    NonCanonicalPair,
    InvalidAmount,
    AmountConversion,
    InvalidFee,
    StaleHeight,
    InsufficientLiquidity,
    InsufficientOutput,
    UnknownPool,
    UnknownShare,
    Unauthorized,
    Collision,
    ArithmeticOverflow,
    Encoding,
}

impl fmt::Display for PoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PoolError {}

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct PoolHash(Hash);

impl PoolHash {
    pub fn derive(asset_x: Pair, asset_y: Pair) -> Result<Self, PoolError> {
        ensure_canonical_pair(asset_x, asset_y)?;
        let bytes = canonical_bytes(&(asset_x, asset_y)).map_err(|_| PoolError::Encoding)?;
        Ok(Self(domain(HashDomain::Pool, &bytes)))
    }

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(Hash::from_bytes(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        self.0.as_bytes()
    }
    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0.into_bytes()
    }
}

impl fmt::Display for PoolHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format("", &self.0, formatter)
    }
}

impl FromStr for PoolHash {
    type Err = HashParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse("", value).map(Self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pool {
    pub asset_x: Pair,
    pub asset_y: Pair,
    pub reserve_x: PoolAmount,
    pub reserve_y: PoolAmount,
    pub total_liquidity: Liquidity,
    pub fee_units: u32,
    /// Height of the valid block that most recently changed reserves or shares.
    pub last_updated_height: Height,
}

impl Pool {
    pub fn new(
        asset_x: Pair,
        asset_y: Pair,
        reserve_x: PoolAmount,
        reserve_y: PoolAmount,
        total_liquidity: Liquidity,
        fee_units: u32,
        last_updated_height: Height,
    ) -> Result<Self, PoolError> {
        let pool = Self {
            asset_x,
            asset_y,
            reserve_x,
            reserve_y,
            total_liquidity,
            fee_units,
            last_updated_height,
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn validate(&self) -> Result<(), PoolError> {
        ensure_canonical_pair(self.asset_x, self.asset_y)?;
        ensure_amount(self.reserve_x)?;
        ensure_amount(self.reserve_y)?;
        ensure_liquidity(self.total_liquidity)?;
        if self.fee_units >= FEE_DENOMINATOR {
            return Err(PoolError::InvalidFee);
        }
        Ok(())
    }

    pub fn id(&self) -> Result<PoolHash, PoolError> {
        PoolHash::derive(self.asset_x, self.asset_y)
    }

    pub fn ensure_transition_height(&self, height: Height) -> Result<(), PoolError> {
        if height < self.last_updated_height {
            Err(PoolError::StaleHeight)
        } else {
            Ok(())
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolShare {
    pub pool: PoolHash,
    pub owner: Address,
    pub amount: Liquidity,
}

impl PoolShare {
    pub fn new(pool: PoolHash, owner: Address, amount: Liquidity) -> Result<Self, PoolError> {
        ensure_liquidity(amount)?;
        Ok(Self {
            pool,
            owner,
            amount,
        })
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct PoolShareHash(Hash);

impl PoolShareHash {
    pub fn derive(pool: PoolHash, commitment: [u8; HASH_SIZE], output_index: u32) -> Self {
        let mut bytes = [0_u8; HASH_SIZE * 2 + 4];
        bytes[..HASH_SIZE].copy_from_slice(pool.as_bytes());
        bytes[HASH_SIZE..HASH_SIZE * 2].copy_from_slice(&commitment);
        bytes[HASH_SIZE * 2..].copy_from_slice(&output_index.to_le_bytes());
        Self(domain(HashDomain::PoolShare, &bytes))
    }

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(Hash::from_bytes(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        self.0.as_bytes()
    }
}

impl fmt::Display for PoolShareHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format("", &self.0, formatter)
    }
}

impl FromStr for PoolShareHash {
    type Err = HashParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse("", value).map(Self)
    }
}

pub fn canonical_pair(a: Pair, b: Pair) -> Result<(Pair, Pair), PoolError> {
    if a == b {
        return Err(PoolError::IdenticalPair);
    }
    Ok(if a < b { (a, b) } else { (b, a) })
}

pub fn ensure_canonical_pair(a: Pair, b: Pair) -> Result<(), PoolError> {
    if a == b {
        Err(PoolError::IdenticalPair)
    } else if a > b {
        Err(PoolError::NonCanonicalPair)
    } else {
        Ok(())
    }
}

pub fn ensure_amount(amount: PoolAmount) -> Result<(), PoolError> {
    if amount.is_zero() {
        Err(PoolError::InvalidAmount)
    } else {
        Ok(())
    }
}

pub fn ensure_liquidity(amount: Liquidity) -> Result<(), PoolError> {
    if amount.is_zero() {
        Err(PoolError::InvalidAmount)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_identity_is_canonical_and_stable() {
        let a = Pair::Asset(Asset::from_bytes([1; HASH_SIZE]));
        let b = Pair::Asset(Asset::from_bytes([2; HASH_SIZE]));
        assert_eq!(canonical_pair(b, a), Ok((a, b)));
        assert_eq!(PoolHash::derive(a, b), PoolHash::derive(a, b));
        assert_eq!(PoolHash::derive(b, a), Err(PoolError::NonCanonicalPair));
        assert_eq!(PoolHash::derive(a, a), Err(PoolError::IdenticalPair));
    }

    #[test]
    fn coin_asset_pair_is_supported_but_coin_coin_is_not() {
        let coin = Pair::Coin;
        let asset = Pair::Asset(Asset::from_bytes([1; HASH_SIZE]));
        assert_eq!(canonical_pair(asset, coin), Ok((coin, asset)));
        assert!(PoolHash::derive(coin, asset).is_ok());
        assert_eq!(PoolHash::derive(coin, coin), Err(PoolError::IdenticalPair));
    }

    #[test]
    fn domain_amount_conversions_are_explicit() {
        let coin = Zeno::from_zeno(42);
        let asset = Unit::from_units(u128::from(u64::MAX) + 1);

        assert_eq!(PoolAmount::from(coin).into_zeno(), Ok(coin));
        assert_eq!(PoolAmount::from(asset).into_unit(), asset);
        assert_eq!(
            PoolAmount::from(asset).into_zeno(),
            Err(PoolError::AmountConversion)
        );
    }
}
