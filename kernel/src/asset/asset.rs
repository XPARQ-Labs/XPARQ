use crate::asset::{AssetHashParseError, AssetMetadata};
use crate::common::domain_hash;
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;
use std::{fmt, str::FromStr};

const ASSET_HASH_CONTEXT: &[u8] = b"XPARQ Native Asset";

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

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct AssetHash([u8; 32]);

impl AssetHash {
    pub fn derive(authority: Address, symbol: &str) -> Self {
        Self(derive_asset_hash(&[&authority.0, symbol.as_bytes()]))
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AssetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_hash(ASSET_HASH_PREFIX, &self.0, formatter)
    }
}

impl FromStr for AssetHash {
    type Err = AssetHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_hash(ASSET_HASH_PREFIX, value).map(Self)
    }
}

/// Definition of one native asset class. Balances live in asset share UTXOs.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub metadata: AssetMetadata,
}

impl Asset {
    pub const fn new(metadata: AssetMetadata) -> Self {
        Self { metadata }
    }
}

pub const ASSET_HASH_SIZE: usize = 32;
pub const ASSET_HASH_PREFIX: &str = "asset:";

pub(crate) fn derive_asset_hash(fields: &[&[u8]]) -> [u8; ASSET_HASH_SIZE] {
    asset_domain_hash(ASSET_HASH_CONTEXT, fields)
}

/// Derives a canonical SHA3-256 digest for an asset-domain object.
///
/// The context and every field are length-prefixed so distinct field layouts
/// cannot produce the same byte stream.
pub fn asset_domain_hash(context: &[u8], fields: &[&[u8]]) -> [u8; ASSET_HASH_SIZE] {
    domain_hash(context, fields)
}

pub(crate) fn format_hash(
    prefix: &str,
    bytes: &[u8; ASSET_HASH_SIZE],
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    formatter.write_str(prefix)?;
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

pub(crate) fn parse_hash(
    prefix: &str,
    value: &str,
) -> Result<[u8; ASSET_HASH_SIZE], AssetHashParseError> {
    let encoded = value.strip_prefix(prefix).ok_or(AssetHashParseError)?;
    if encoded.len() != ASSET_HASH_SIZE * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AssetHashParseError);
    }

    let mut bytes = [0; ASSET_HASH_SIZE];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_nibble(encoded.as_bytes()[offset]).ok_or(AssetHashParseError)? << 4)
            | hex_nibble(encoded.as_bytes()[offset + 1]).ok_or(AssetHashParseError)?;
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_has_a_stable_test_vector() {
        assert_eq!(
            derive_asset_hash(&[b"field one", b"field two"]),
            [
                73, 46, 135, 68, 53, 170, 54, 28, 186, 232, 136, 226, 149, 89, 216, 139, 103, 97,
                147, 220, 43, 185, 230, 207, 122, 70, 233, 105, 233, 65, 52, 65,
            ]
        );
    }

    #[test]
    fn text_format_is_explicit_and_canonical() {
        let canonical = format!("{ASSET_HASH_PREFIX}{}", "ab".repeat(ASSET_HASH_SIZE));
        assert!(parse_hash(ASSET_HASH_PREFIX, &canonical).is_ok());
        assert!(parse_hash(ASSET_HASH_PREFIX, &"ab".repeat(ASSET_HASH_SIZE)).is_err());
        assert!(
            parse_hash(
                ASSET_HASH_PREFIX,
                &format!("ASSET:{}", "ab".repeat(ASSET_HASH_SIZE))
            )
            .is_err()
        );
        assert!(
            parse_hash(
                ASSET_HASH_PREFIX,
                &format!("{ASSET_HASH_PREFIX}{}", "AB".repeat(ASSET_HASH_SIZE))
            )
            .is_err()
        );
    }
}
