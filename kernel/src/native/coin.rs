use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, HASH_SIZE, Hash, HashDomain, HashParseError, domain, format, parse};
use std::{fmt, str::FromStr};

pub const DECIMALS: u8 = 6;
pub const COIN_PREFIX: &str = "XPQ:";

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
pub struct Zeno(u64);

impl Zeno {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);

    pub const fn from_zeno(zeno: u64) -> Self {
        Self(zeno)
    }

    pub const fn as_zeno(self) -> u64 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(zeno) => Some(Self(zeno)),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(zeno) => Some(Self(zeno)),
            None => None,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct XPARQCoin(Hash);

impl XPARQCoin {
    pub const SIZE: usize = HASH_SIZE;
    pub const ZENO_PER_COIN: u64 = 10u64.pow(DECIMALS as u32);

    pub fn from_emission_origin(origin: &[u8; HASH_SIZE]) -> Self {
        Self(domain(HashDomain::Emission, origin))
    }

    pub fn from_output(commitment: &[u8; HASH_SIZE], index: u32) -> Self {
        let mut bytes = [0_u8; HASH_SIZE + 4];

        bytes[..HASH_SIZE].copy_from_slice(commitment);
        bytes[HASH_SIZE..].copy_from_slice(&index.to_le_bytes());

        Self(domain(HashDomain::Output, &bytes))
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

impl From<Hash> for XPARQCoin {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<XPARQCoin> for Hash {
    fn from(coin: XPARQCoin) -> Self {
        coin.0
    }
}

impl fmt::Display for XPARQCoin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format(COIN_PREFIX, &self.0, formatter)
    }
}

impl FromStr for XPARQCoin {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse(COIN_PREFIX, value).map(Self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Address(Address),
    BlockMiner,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub output: Recipient,
    pub amount: Zeno,
}

impl Output {
    pub const fn new(recipient: Address, amount: Zeno) -> Self {
        Self {
            output: Recipient::Address(recipient),
            amount,
        }
    }

    pub const fn block_miner(amount: Zeno) -> Self {
        Self {
            output: Recipient::BlockMiner,
            amount,
        }
    }
}

pub use XPARQCoin as XPQ;
