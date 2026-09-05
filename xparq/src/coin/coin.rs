use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};
use std::{fmt, str::FromStr};

use crate::coin::CoinHashParseError;

pub const COIN_NAME: &str = "XPARQ Coin";
pub const COIN_SYMBOL: &str = "XPQ";
pub const UNIT_NAME: &str = "zeno";
pub const DECIMALS: u8 = 6;
pub const ZENO: u64 = 1;

const _: () = assert!(ZENO == 1);

pub struct XPARQCoin;

impl XPARQCoin {
    pub const ZENO_PER_COIN: u64 = 10u64.pow(DECIMALS as u32);
}

pub use XPARQCoin as XPQ;

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

pub const COIN_HASH_SIZE: usize = 32;
pub const COIN_HASH_PREFIX: &str = "XPQ:";

const COIN_HASH_CONTEXT: &[u8] = b"XPARQ Native Coin";
const TRANSACTION_OUTPUT_DOMAIN: &[u8] = b"XPARQ transaction output";
const EMISSION_DOMAIN: &[u8] = b"XPARQ Emission";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct CoinHash([u8; COIN_HASH_SIZE]);

impl CoinHash {
    pub const SIZE: usize = COIN_HASH_SIZE;

    pub fn from_emission_origin(origin: &[u8; COIN_HASH_SIZE]) -> Self {
        Self::derive(&[EMISSION_DOMAIN, origin])
    }

    pub fn from_output(commitment: &[u8; COIN_HASH_SIZE], index: u32) -> Self {
        Self::from_tagged_output(b"output", commitment, index)
    }

    pub fn from_change(commitment: &[u8; COIN_HASH_SIZE], index: u32) -> Self {
        Self::from_tagged_output(b"change", commitment, index)
    }

    fn from_tagged_output(tag: &[u8], commitment: &[u8; COIN_HASH_SIZE], index: u32) -> Self {
        Self::derive(&[
            TRANSACTION_OUTPUT_DOMAIN,
            tag,
            commitment,
            &index.to_le_bytes(),
        ])
    }

    fn derive(fields: &[&[u8]]) -> Self {
        let mut hasher = Sha3_256::new();

        hasher.update(&(COIN_HASH_CONTEXT.len() as u64).to_le_bytes());
        hasher.update(COIN_HASH_CONTEXT);

        for field in fields {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }

        let digest = hasher.finalize();

        let mut bytes = [0u8; COIN_HASH_SIZE];
        bytes.copy_from_slice(&digest);

        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; COIN_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; COIN_HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; COIN_HASH_SIZE] {
        self.0
    }
}

impl fmt::Display for CoinHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(COIN_HASH_PREFIX)?;

        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl FromStr for CoinHash {
    type Err = CoinHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .strip_prefix(COIN_HASH_PREFIX)
            .ok_or(CoinHashParseError)?;

        if value.len() != COIN_HASH_SIZE * 2 {
            return Err(CoinHashParseError);
        }

        let encoded = value.as_bytes();
        let mut bytes = [0; COIN_HASH_SIZE];

        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;

            let high = hex_nibble(encoded[offset]).ok_or(CoinHashParseError)?;

            let low = hex_nibble(encoded[offset + 1]).ok_or(CoinHashParseError)?;

            *byte = (high << 4) | low;
        }

        Ok(Self(bytes))
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// One concrete native XPQ coin object.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Coin {
    pub utxo: CoinHash,
    pub amount: Zeno,
}

impl Coin {
    pub const fn new(utxo: CoinHash, amount: Zeno) -> Self {
        Self { utxo, amount }
    }

    pub const fn is_zero(self) -> bool {
        self.amount.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denomination_is_correct() {
        assert_eq!(XPARQCoin::ZENO_PER_COIN, 1_000_000);

        assert_eq!(XPQ::ZENO_PER_COIN, 1_000_000);
    }

    #[test]
    fn zeno_round_trip() {
        let amount = Zeno::from_zeno(1_000_000);

        assert_eq!(amount.as_zeno(), 1_000_000);
    }

    #[test]
    fn one_xpq_is_one_million_zeno() {
        let one_xpq = Zeno::from_zeno(XPQ::ZENO_PER_COIN);

        assert_eq!(one_xpq.as_zeno(), 1_000_000);
    }

    #[test]
    fn output_and_change_are_domain_separated() {
        let commitment = [7u8; COIN_HASH_SIZE];

        let output = CoinHash::from_output(&commitment, 0);

        let change = CoinHash::from_change(&commitment, 0);

        assert_ne!(output, change);
    }

    #[test]
    fn output_index_changes_coin_hash() {
        let commitment = [7u8; COIN_HASH_SIZE];

        let first = CoinHash::from_output(&commitment, 0);

        let second = CoinHash::from_output(&commitment, 1);

        assert_ne!(first, second);
    }
}
