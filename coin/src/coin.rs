use borsh::{BorshDeserialize, BorshSerialize};
use std::{fmt, str::FromStr};

use crate::CoinIdParseError;

pub const COIN_NAME: &str = "XPQ";
pub const UNIT_NAME: &str = "paqs";
pub const UNIT: u64 = 1;
pub const COIN: u64 = 1_000_000;
pub const DECIMALS: u8 = 6;

const _: () = assert!(COIN == 1_000_000);
const _: () = assert!(UNIT == 1);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Amount(pub u64);

impl Amount {
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

pub const COIN_ID_SIZE: usize = blake3::OUT_LEN;
const COIN_ID_CONTEXT: &str = "XPARQ CoinId v1";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct CoinId([u8; COIN_ID_SIZE]);

impl CoinId {
    pub const SIZE: usize = COIN_ID_SIZE;

    /// Derives an identifier from unambiguous length-delimited fields.
    pub fn derive(fields: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(COIN_ID_CONTEXT);
        for field in fields {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        Self(*hasher.finalize().as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; COIN_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; COIN_ID_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; COIN_ID_SIZE] {
        self.0
    }
}

impl fmt::Display for CoinId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for CoinId {
    type Err = CoinIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != COIN_ID_SIZE * 2 {
            return Err(CoinIdParseError);
        }

        let encoded = value.as_bytes();
        let mut bytes = [0; COIN_ID_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            let high = hex_nibble(encoded[offset]).ok_or(CoinIdParseError)?;
            let low = hex_nibble(encoded[offset + 1]).ok_or(CoinIdParseError)?;
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

/// A minimal coin primitive: an immutable identifier paired with an amount.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Coin {
    pub id: CoinId,
    pub amount: Amount,
}

impl Coin {
    pub const fn new(id: CoinId, amount: Amount) -> Self {
        Self { id, amount }
    }

    pub const fn is_zero(self) -> bool {
        self.amount.0 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_checked_arithmetic_preserves_the_amount_type() {
        assert_eq!(Amount(2).checked_add(Amount(3)), Some(Amount(5)));
        assert_eq!(Amount(u64::MAX).checked_add(Amount(1)), None);
        assert_eq!(Amount(5).checked_sub(Amount(3)), Some(Amount(2)));
        assert_eq!(Amount(0).checked_sub(Amount(1)), None);
    }

    #[test]
    fn coin_id_text_round_trips() {
        let id = CoinId::derive(&[b"field one", b"field two"]);
        assert_eq!(id.to_string().parse::<CoinId>(), Ok(id));
    }

    #[test]
    fn coin_id_parser_rejects_non_ascii_without_panicking() {
        let non_ascii_with_valid_byte_length = format!("{}{}", "0".repeat(61), "\u{20ac}");
        assert_eq!(non_ascii_with_valid_byte_length.len(), COIN_ID_SIZE * 2);
        assert_eq!(
            non_ascii_with_valid_byte_length.parse::<CoinId>(),
            Err(CoinIdParseError)
        );
    }
}
